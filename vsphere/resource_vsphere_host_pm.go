package vsphere

import (
	"context"
	"fmt"
	"log"

	gowbem	"github.com/MagicLeo21/GoWBEM/src/gowbem"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-provider-vsphere/vsphere/internal/helper/datacenter"
	"github.com/hashicorp/terraform-provider-vsphere/vsphere/internal/helper/hostsystem"
	"github.com/vmware/govmomi/vim25/methods"
	"github.com/vmware/govmomi/vim25/types"
)

func resourceVsphereHostPm() *schema.Resource {
	return &schema.Resource{
		Create: resourceVsphereHostPmCreate,
		Read:   resourceVsphereHostPmRead,
		Update: resourceVsphereHostPmUpdate,
		Delete: resourceVsphereHostPmDelete,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},
		Schema: map[string]*schema.Schema {
			"datacenter": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Datacenter name",
			},
			"hostname": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "FQDN or IP address of the host.",
			},
			"host_username": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Username of the administration account of the host.",
			},
			"host_password": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Password of the administration account of the host.",
				Sensitive:   true,
			},
			"bmc_username": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Username of the administration account of the BMC.",
			},
			"bmc_password": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Password of the administration account of the BMC.",
				Sensitive:   true,
			},
		},
	}
}


func getHostBmcInfo(d *schema.ResourceData) (*types.HostIpmiInfo, error){

	hostname := d.Get("hostname").(string)
	host_username := d.Get("host_username").(string)
	host_password := d.Get("host_password").(string)
	bmc_username := d.Get("bmc_username").(string)
	bmc_password := d.Get("bmc_password").(string)

	wbemUrl := fmt.Sprintf("https://%s:%s@%s:5989/cimom", host_username, host_password, hostname)
	log.Printf("Trying %s\n", wbemUrl)
	wbemConnection,err := gowbem.NewWBEMConn(wbemUrl)
	if err != nil {
		log.Printf("NewWBEMConn : %v\n\n", err)
		return nil, err
	}
	wbemConnection.SetNamespace("root/cimv2")
	classPath := "OMC_IPMIIPProtocolEndpoint"
	className := gowbem.ClassName {
		Name: classPath,
	}
	values, err := wbemConnection.EnumerateInstances( &className, false, false, nil)
	if err != nil {
		log.Printf("methodCall : %v\n", err)
		return nil, err
	}
	count := 0
	ipmiInfo := types.HostIpmiInfo{
		Login: bmc_username,
		Password: bmc_password,
	}
	for _, property := range values[0].Instance.Property {
		if property.Value != nil {
			log.Printf ("%s: %s\n", property.Name, (property.Value.Value))
		}
		if strings.Compare(property.Name, "IPv4Address") == 0 {
			ipmiInfo.BmcIpAddress = property.Value.Value
			count ++
		}
		if strings.Compare(property.Name, "MACAddress") == 0 {
			ipmiInfo.BmcMacAddress =  property.Value.Value
			count ++
		}
		if count == 2 {
			break
		}
	}
	return &ipmiInfo, nil
}

func resourceVsphereHostPmCreate(d *schema.ResourceData, meta interface{}) error {
	err := validateFields(d)
	if err != nil {
		return err
	}

	client := meta.(*Client).vimClient

	ipmiInfo, err := getHostBmcInfo(d)

	hostname := d.Get("hostname").(string)
	dcName := d.Get("datacenter").(string)
	dc,err := datacenter.FromPath(client, dcName)
	if err != nil {
		return err
	}

	hostSystem, err := hostsystem.SystemOrDefault(client, hostname, dc)
	if err != nil {
		return err
	}

	req := &types.UpdateIpmi{}
	req.This = hostSystem.Reference()
	req.IpmiInfo = *ipmiInfo
	methods.UpdateIpmi(context.TODO(), hostSystem.Client(), req)

	d.SetId(fmt.Sprintf("%s_ipmi",hostname))
	return nil
}

func resourceVsphereHostPmRead(d *schema.ResourceData, meta interface{}) error {
/*
	// NOTE: Destroying the host without telling vsphere about it will result in us not
	// knowing that the host does not exist any more.

	// Look for host
	client := meta.(*Client).vimClient
	hostID := d.Id()

	// Find host and get reference to it.
	hs, err := hostsystem.FromID(client, hostID)
	if err != nil {
		if viapi.IsManagedObjectNotFoundError(err) {
			d.SetId("")
			return nil
		}
		return fmt.Errorf("error while searching host %s. Error: %s ", hostID, err)
	}

	maintenanceState, err := hostsystem.HostPmInMaintenance(hs)
	if err != nil {
		return fmt.Errorf("error while checking maintenance status for host %s. Error: %s", hostID, err)
	}
	_ = d.Set("maintenance", maintenanceState)

	// Retrieve host's properties.
	log.Printf("[DEBUG] Got host %s", hs.String())
	host, err := hostsystem.Properties(hs)
	if err != nil {
		return fmt.Errorf("error while retrieving properties for host %s. Error: %s", hostID, err)
	}

	if host.Parent != nil && host.Parent.Type == "ClusterComputeResource" && !d.Get("cluster_managed").(bool) {
		_ = d.Set("cluster", host.Parent.Value)
	} else {
		_ = d.Set("cluster", "")
	}

	connectionState, err := hostsystem.GetConnectionState(hs)
	if err != nil {
		return fmt.Errorf("error while getting connection state for host %s. Error: %s", hostID, err)
	}

	if connectionState == types.HostPmSystemConnectionStateDisconnected {
		// Config and LicenseManager cannot be used while the host is
		// disconnected.
		_ = d.Set("connected", false)
		return nil
	}
	_ = d.Set("connected", true)

	lockdownMode, err := hostLockdownString(host.Config.LockdownMode)
	if err != nil {
		return err
	}

	log.Printf("Setting lockdown to %s", lockdownMode)
	_ = d.Set("lockdown", lockdownMode)

	licenseKey := d.Get("license").(string)
	if licenseKey != "" {
		licFound, err := isLicenseAssigned(client.Client, hostID, licenseKey)
		if err != nil {
			return fmt.Errorf("error while checking license assignment for host %s. Error: %s", hostID, err)
		}

		if !licFound {
			_ = d.Set("license", "")
		}
	}

	// Read tags
	if tagsClient, _ := meta.(*Client).TagsManager(); tagsClient != nil {
		if err := readTagsForResource(tagsClient, host, d); err != nil {
			return fmt.Errorf("error reading tags: %s", err)
		}
	}

	// Read custom attributes
	if customattribute.IsSupported(client) {
		moHostPm, err := hostsystem.Properties(hs)
		if err != nil {
			return err
		}
		customattribute.ReadFromResource(moHostPm.Entity(), d)
	}
*/
	return nil
}

func resourceVsphereHostPmUpdate(d *schema.ResourceData, meta interface{}) error {
/*
	err := validateFields(d)
	if err != nil {
		return err
	}

	client := meta.(*Client).vimClient

	tagsClient, err := tagsManagerIfDefined(d, meta)
	if err != nil {
		return err
	}

	attrsProcessor, err := customattribute.GetDiffProcessorIfAttributesDefined(client, d)
	if err != nil {
		return err
	}

	// First let's establish where we are and where we want to go
	var desiredConnectionState bool
	if d.HasChange("connected") {
		_, newVal := d.GetChange("connected")
		desiredConnectionState = newVal.(bool)
	} else {
		desiredConnectionState = d.Get("connected").(bool)
	}

	hostID := d.Id()
	hostObject, err := hostsystem.FromID(client, hostID)
	if err != nil {
		return fmt.Errorf("error while retrieving HostPmSystem object for host ID %s. Error: %s", hostID, err)
	}

	actualConnectionState, err := hostsystem.GetConnectionState(hostObject)
	if err != nil {
		return fmt.Errorf("error while retrieving connection state for host %s. Error: %s", hostID, err)
	}

	// Have there been any changes that warrant a reconnect?
	reconnect := false
	connectionKeys := []string{"hostname", "username", "password", "thumbprint"}
	for _, k := range connectionKeys {
		if d.HasChange(k) {
			reconnect = true
			break
		}
	}

	// Decide if we're going to reconnect or not
	reconnectNeeded, err := shouldReconnect(d, meta, actualConnectionState, desiredConnectionState, reconnect)
	if err != nil {
		return err
	}

	switch reconnectNeeded {
	case 1:
		err := resourceVSphereHostPmReconnect(d, meta)
		if err != nil {
			return fmt.Errorf("error while reconnecting host %s. Error: %s", hostID, err)
		}
	case -1:
		err := resourceVSphereHostPmDisconnect(d, meta)
		if err != nil {
			return fmt.Errorf("error while disconnecting host %s. Error: %s", hostID, err)
		}
	case 0:
		break
	}

	mutableKeys := map[string]func(*schema.ResourceData, interface{}, interface{}, interface{}) error{
		"license":     resourceVSphereHostPmUpdateLicense,
		"cluster":     resourceVSphereHostPmUpdateCluster,
		"maintenance": resourceVSphereHostPmUpdateMaintenanceMode,
		"lockdown":    resourceVSphereHostPmUpdateLockdownMode,
		"thumbprint":  resourceVSphereHostPmUpdateThumbprint,
	}
	for k, v := range mutableKeys {
		log.Printf("[DEBUG] Checking if key %s changed", k)
		if !d.HasChange(k) {
			continue
		}
		log.Printf("[DEBUG] Key %s has change, processing", k)
		old, newVal := d.GetChange(k)
		err := v(d, meta, old, newVal)
		if err != nil {
			return fmt.Errorf("error while updating %s: %s", k, err)
		}
	}

	// Apply tags
	if tagsClient != nil {
		if err := processTagDiff(tagsClient, d, hostObject); err != nil {
			return fmt.Errorf("error updating tags: %s", err)
		}
	}

	// Apply custom attributes
	if attrsProcessor != nil {
		if err := attrsProcessor.ProcessDiff(hostObject); err != nil {
			return err
		}
	}
*/
	return resourceVsphereHostPmRead(d, meta)
}

func resourceVsphereHostPmDelete(d *schema.ResourceData, meta interface{}) error {
/*
	client := meta.(*Client).vimClient
	hostID := d.Id()

	hs, err := hostsystem.FromID(client, hostID)
	if err != nil {
		return fmt.Errorf("error while retrieving HostPmSystem object for host ID %s. Error: %s", hostID, err)
	}

	connectionState, err := hostsystem.GetConnectionState(hs)
	if err != nil {
		return fmt.Errorf("error while retrieving connection state for host %s. Error: %s", hostID, err)
	}

	if connectionState != types.HostPmSystemConnectionStateDisconnected {
		// We cannot put a disconnected server in maintenance mode.
		err = resourceVSphereHostPmDisconnect(d, meta)
		if err != nil {
			return fmt.Errorf("error while disconnecting host: %s", err.Error())
		}
	}

	hostProps, err := hostsystem.Properties(hs)
	if err != nil {
		return fmt.Errorf("error while retrieving properties fort host %s. Error: %s", hostID, err)
	}

	// If this is a standalone host we need to destroy the ComputeResource object
	// and not the HostPmsystem itself.
	var task *object.Task
	if hostProps.Parent.Type == "ComputeResource" {
		cr := object.NewComputeResource(client.Client, *hostProps.Parent)
		task, err = cr.Destroy(context.TODO())
		if err != nil {
			return fmt.Errorf("error while submitting destroy task for compute resource %s. Error: %s", hostProps.Parent.Value, err)
		}
	} else {
		task, err = hs.Destroy(context.TODO())
		if err != nil {
			return fmt.Errorf("error while submitting destroy task for host system %s. Error: %s", hostProps.Parent.Value, err)
		}
	}
	p := property.DefaultCollector(client.Client)
	_, err = gtask.Wait(context.TODO(), task.Reference(), p, nil)
	if err != nil {
		return fmt.Errorf("error while waiting for host (%s) to be removed: %s", hostID, err)
	}
*/
	return nil
}
