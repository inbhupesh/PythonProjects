#sys.path.append('/opt/esl/lib/')
import logging
import traceback
import os
import argparse
import msal, cx_Oracle
import datetime, json
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from esl import *
import asyncio, aiohttp
import psutil, statistics

myProcess = psutil.Process(os.getpid())
project_path = ''

# proxy = 'http://proxy-emea.svcs.entsvcs.com:8088'
# os.environ['http_proxy'] = proxy
# os.environ['HTTP_PROXY'] = proxy
# os.environ['https_proxy'] = proxy
# os.environ['HTTPS_PROXY'] = proxy

parser = argparse.ArgumentParser()
parser.add_argument(
    '-s', '--subscription_id', type=str,
    help="Specify the Subscription ID of the Customer to Want to collect the Azure VM Details for",
)
parser.add_argument(
    '-t', '--test',
    help="Run the script in test mode ensuring NO COMMITS to the Database",
    action="store_true",
    default=False,
)
debug_verbose_group = parser.add_mutually_exclusive_group()
debug_verbose_group.add_argument(
    '-d', '--debug',
    help="Print lots of debugging statements",
    action="store_true",
    default=False,
)
debug_verbose_group.add_argument(
    '-v', '--verbose',
    help="Be verbose",
    action="store_true",
    default=False,
)
args = parser.parse_args()
mem=set()
cpu=set()
db_con_time=0

def resourceutil():
    global mem, cpu
    mem.add((myProcess.memory_info().rss)/1000000)
    cpu.add(myProcess.cpu_percent() / psutil.cpu_count())

def log_filter(record):
    # Exclude log messages with the traceback format
    if record.levelno == logging.ERROR and "Traceback" in record.getMessage():
        return False
    return True

def setup_logging(args):
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.DEBUG)
    if args.verbose:
        level = logging.INFO
        console_handler = logging.StreamHandler()
        console_handler.setLevel(level)
        console_handler.addFilter(log_filter)
        formatter = logging.Formatter('%(levelname)s: %(message)s')
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)
    if args.debug:
        level = logging.DEBUG
        console_handler = logging.StreamHandler()
        console_handler.setLevel(level)
        console_handler.addFilter(log_filter)
        formatter = logging.Formatter('%(levelname)s: %(message)s')
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)

    log_file_name = project_path + "test_logs.log"
    file_handler = logging.FileHandler(log_file_name, mode='w')
    file_handler.setLevel(logging.INFO)
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s',"%Y-%m-%d %H:%M:%S")
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    logger.propagate = False

    return logger

def getKey():
    logger.debug("Attempting to unpack azure credentials")
    try:
        cred = {}
        private_key = None
        with open(project_path + "esl_private_key.pem", "rb") as key_file:
            private_key = serialization.load_pem_private_key(key_file.read(), password=None, backend=default_backend())
        with open(project_path + 'azure.bin', "rb") as bin_file:
            data = bin_file.read()
        original_message = private_key.decrypt(data, padding.OAEP(padding.MGF1(hashes.SHA256()), hashes.SHA256(), None))
        cred = json.loads(original_message.decode('utf8'))
        return cred
    except:
        logger.error("Could not unpack the azure credentials... moving on to next subscription")
        logger.error("Traceback:\n%s", traceback.format_exc())

# Get Azure access token using Service Principal credentials
def get_token(tenantid, clientid, clientsecret):
    logger.info("Trying to get the access token")
    try:
        app = msal.ConfidentialClientApplication(
        clientid,
        authority=f'https://login.microsoftonline.com/{tenantid}',
        client_credential=clientsecret)
        result = app.acquire_token_for_client(scopes=["https://management.azure.com/.default"])
        logger.info("Got the access token, returning back to the get_vm_details() function")
        return result
    except:
        logger.error("could not get the access token... moving on to next subscription")
        logger.error("Traceback:\n%s", traceback.format_exc())

# Below function ensures every page of API response is read and collected
async def get_recursive_response(session, url, headers, data):
    async with session.get(url, headers=headers) as resp:
        try:
            response = await resp.json()
            data["value"].extend([item for item in response.get("value", [])])

            while 'nextLink' in response:
                url = response['nextLink']
                async with session.get(url, headers=headers) as next_resp:
                    try:
                        response = await next_resp.json()
                        data["value"].extend([item for item in response.get("value", [])])
                    except:
                        logger.error("Could not process 'NextLink', continuing the program without reading the next page")
                        logger.error("Traceback:\n%s", traceback.format_exc())
        except:
            logger.error("Could not process initial request")
            logger.error("Traceback:\n%s", traceback.format_exc())

    return data  

def get_db_connection():
    global db_con_time
    start_time=datetime.datetime.now().timestamp()
    logger.info("Trying to establish the connection with the database")
    try:
        # k=DBConnect('esl')
        k=cx_Oracle.connect('john', 'admin', 'localhost:1521/xe')
        logger.info("Connected to the Database Successfully")
        logger.info(f"Time Elapsed in Getting DB Connection: {int(datetime.datetime.now().timestamp() - start_time)} Seconds")
        db_con_time+=int(datetime.datetime.now().timestamp() - start_time)
        return k
    except:
        logger.error("Could not establish the connection to the database... moving on to next subscription")
        logger.error("Traceback:\n%s", traceback.format_exc())

def get_tenant_subscription_ids(subscription_id):
    logger.debug("Inside get_tenant_subscription_ids() function")
    k=get_db_connection()
    resourceutil()
    # connection = k.con
    connection = k
    cursor = k.cursor()
    if subscription_id == 'all':
        logger.info("No Subscription ID Specified, Program Will Run for All the Subscriptions")
        # Execute the SQL query to retrieve tenant_id and subscription_id
        try:
            cursor.execute("SELECT tenant_id, subscription_id, subscription_name FROM john.Azure_Instances")
            rows = cursor.fetchall()
            if not rows:
                raise Exception("Data Does not returned the any Subscription Info (Tenant, Name) from Instances Tables")
            else:
                logger.debug("Got the Tenant & Subscription ID from the DB")
        except:
            logger.error("Could Not Get the Tenants & Subscriptions from the Database... moving on to next subscription")
            logger.error("Traceback:\n%s", traceback.format_exc())
    else:
        logger.info("Subscription ID is Specified, Program Will Run only for the Specified Subscription")
        # Execute the SQL query to retrieve tenant_id and subscription_id for a specified subscription id at the terminal
        try:
            cursor.execute(f"SELECT tenant_id, subscription_id, subscription_name FROM john.Azure_Instances WHERE subscription_id='{subscription_id}'")
            rows = cursor.fetchall()
            if not rows:
                raise Exception(f"No Subscription Info (Tenant, Name) Found in Instances Table for provided Subscription ID: {subscription_id}")
            else:
                logger.debug(f"Got the Tenant & Subscription ID from the DB for the Subscription '{subscription_id}'")
        except:
            logger.error(f"Could Not Get the Tenants & Subscriptions from the Database for the Subscription '{subscription_id}' ... moving on to next subscription")
            logger.error("Traceback:\n%s", traceback.format_exc())

    # Close the cursor and connection
    cursor.close()
    connection.close()
    return rows

# Get the VMs for each subscription
async def get_vm_details(subscription_id):
    logger.debug("Starting to execute get_vm_details() function")
    # Azure API endpoints
    # SUBSCRIPTIONS_ENDPOINT = 'https://management.azure.com/subscriptions?api-version=2022-12-01'
    VM_ENDPOINT = 'https://management.azure.com/subscriptions/{subscription_id}/providers/Microsoft.Compute/virtualMachines?api-version=2023-03-01'
    PUBLIC_NW_ENDPOINT = "https://management.azure.com/subscriptions/{subscription_id}/providers/Microsoft.Network/publicIPAddresses?api-version=2022-11-01"
    PRIVATE_NW_ENDPOINT = "https://management.azure.com/subscriptions/{subscription_id}/providers/Microsoft.Network/networkInterfaces?api-version=2022-11-01"
    VM_STATUS_ENDPOINT = "https://management.azure.com/subscriptions/{subscription_id}/providers/Microsoft.Compute/virtualMachines?api-version=2023-03-01&statusOnly=true"
    SKU_ENDPOINT = "https://management.azure.com/subscriptions/{subscription_id}/providers/Microsoft.Compute/skus?api-version=2021-07-01"
    SUBNET_ENDPOINT = "https://management.azure.com/subscriptions/{subscription_id}/providers/Microsoft.Network/virtualNetworks?api-version=2021-02-01"
    DISKSIZE_ENDPOINT = "https://management.azure.com/subscriptions/{subscription_id}/providers/Microsoft.Compute/disks?api-version=2021-04-01"
    
    vm_details = []
    # headers_keys=[]
    logger.info("Starting to identify the scope of work (subscription ids to work on)...")
    if subscription_id is None:
        subscription_id="all"
        scope=get_tenant_subscription_ids(subscription_id)
        resourceutil()
    else:
        scope=get_tenant_subscription_ids(subscription_id)
        resourceutil()
    logger.debug("Scope recieved, starting to work on it")
    semaphore = asyncio.Semaphore(5)  # Limit concurrent requests to 5

    async def process_customer(customer, semaphore):
        tenant_id, subscription_id, subscription_name = customer
        # Get the azure credentials
        logger.info(f"Starting to work on the Subscription: '{subscription_name}'")
        k=getKey()
        clientid=k['client_id']
        clientsecret=k['client_secret']
        result=get_token(tenant_id, clientid, clientsecret)
        if result is not None: 
            headers = {"Authorization": f"Bearer {result['access_token']}", "Content-Type": "application/json"}
            last_loaded=str(datetime.date.today())

            async with semaphore:
                async with aiohttp.ClientSession() as session:
                    tasks = []
                    # Send GET requests and retrieve the JSON responses concurrently
                    logger.info("Trying to get API Response for VM, Network, SKU, DiskSize, etc...")
                    tasks.append(get_recursive_response(session, VM_ENDPOINT.format(subscription_id=subscription_id), headers, data={"value":[]}))
                    tasks.append(get_recursive_response(session, PUBLIC_NW_ENDPOINT.format(subscription_id=subscription_id), headers, data={"value":[]}))
                    tasks.append(get_recursive_response(session, PRIVATE_NW_ENDPOINT.format(subscription_id=subscription_id), headers, data={"value":[]}))
                    tasks.append(get_recursive_response(session, VM_STATUS_ENDPOINT.format(subscription_id=subscription_id), headers, data={"value":[]}))
                    tasks.append(get_recursive_response(session, SKU_ENDPOINT.format(subscription_id=subscription_id), headers, data={"value":[]}))
                    tasks.append(get_recursive_response(session, SUBNET_ENDPOINT.format(subscription_id=subscription_id), headers, data={"value":[]}))
                    tasks.append(get_recursive_response(session, DISKSIZE_ENDPOINT.format(subscription_id=subscription_id), headers, data={"value":[]}))

                    # Wait for all tasks to complete and gather the results
                    results = await asyncio.gather(*tasks)
                    resourceutil()

                    # Process the responses...
                    vms_response = results[0]
                    pub_nw_response = results[1]
                    pvt_nw_response = results[2]
                    vms_status_response = results[3]
                    sku_response = results[4]
                    subnet_response = results[5]
                    disksize_response = results[6]

                # Filter and extract virtual machines sizes configurations from the response
                try:
                    logger.debug(f"Proccessing the SKU_ENDPOINT Data for Subscription: {subscription_name}")
                    vm_specs = {}
                    for obj in sku_response['value']:
                        if obj.get("resourceType") == "virtualMachines":
                            vm_name = obj.get("name")
                            vm_location = obj.get("locations")[0]
                            vm_capabilities = obj.get("capabilities", [])

                            vm_properties = {
                                "name":vm_name,
                                "location":vm_location,
                                "MemoryGB": next((cap.get("value") for cap in vm_capabilities if cap.get("name") == "MemoryGB"), None),
                                "vCPUsAvailable": next((cap.get("value") for cap in vm_capabilities if cap.get("name") == "vCPUsAvailable"), None),
                                "vCPUsPerCore": next((cap.get("value") for cap in vm_capabilities if cap.get("name") == "vCPUsPerCore"), None),
                                "CpuArchitectureType": next((cap.get("value") for cap in vm_capabilities if cap.get("name") == "CpuArchitectureType"), None),
                                "resourceType": obj.get("resourceType"),
                                "tier": obj.get("tier"),
                                "size": obj.get("size"),
                                "family": obj.get("family"),
                            }
                            key=(vm_name+"_"+vm_location).upper()
                            vm_specs[key]=vm_properties
                except:
                    logger.error(f"Could not proccess the data for SKU_ENDPOINT, countinuing the program without it for Subscription: {subscription_name}")
                    logger.error("Traceback:\n%s", traceback.format_exc())

                #get network info before hand
                try:
                    logger.debug(f"Proccessing the PUBLIC_NW_ENDPOINT Data for Subscription: {subscription_name}")
                    network_interfaces = {}
                    for nw in pub_nw_response['value']:
                        try:
                            network_interface_id = nw['properties']['ipConfiguration']['id'].rsplit('/', 2)[0]
                            network_interfaces[network_interface_id] = nw
                        except (KeyError, TypeError, IndexError):
                            network_interface_id = None
                except:
                    logger.error(f"Could not proccess the data for PUBLIC_NW_ENDPOINT, countinuing the program without it for Subscription: {subscription_name}")
                    logger.error("Traceback:\n%s", traceback.format_exc())

                # Prepare the subnet data
                try:
                    logger.debug(f"Proccessing the SUBNET_ENDPOINT Data for Subscription: {subscription_name}")
                    subnets = [subnet for subnet in subnet_response['value'] ]
                except:
                    logger.error(f"Could not proccess the data for SUBNET_ENDPOINT, countinuing the program without it for Subscription: {subscription_name}")
                    logger.error("Traceback:\n%s", traceback.format_exc())

                #Get VM Details
                vm_attributes = {
                        'subscription_id' : [None],
                        'subscription_name' : [None],
                        'resource_group': ['id',  'split', '/', 4],
                        'vm_id': ['properties', 'vmId'],
                        'vm_name': ['name'],
                        'location': ['location'],
                        'vmsize': ['properties', 'hardwareProfile', 'vmSize'],
                        'vm_status' : [None],
                        'VM_Creation_Date' : ['properties', 'timeCreated', 'split', 'T', 0],
                        'os_build_source' : ['properties', 'storageProfile', 'osDisk', 'createOption'],
                        'img_os_publisher': ['properties', 'storageProfile', 'imageReference', 'publisher'],
                        'img_os_offer': ['properties', 'storageProfile', 'imageReference', 'offer'],
                        'img_os_sku': ['properties', 'storageProfile', 'imageReference', 'sku'],
                        'img_os_version': ['properties', 'storageProfile', 'imageReference', 'version'],
                        'img_os_exact_version': ['properties', 'storageProfile', 'imageReference', 'exactVersion'],
                        'os_type': ['properties', 'storageProfile', 'osDisk', 'osType'],
                        'CpuArchitectureType' : [None],
                        'ins_OS_Name' : [None],
                        'ins_OS_Version' : [None],
                        'vmAgentVersion' : [None],
                        'vmAgent_code' : [None],
                        'vmAgent_status' : [None],
                        'vmAgent_message' : [None],
                        'network_interface' : ['properties', 'networkProfile', 'networkInterfaces', 0 , 'id', 'split', '/', 8],
                        'networkSecurityGroup' : [None],
                        'subnet_id' : [None],
                        'subnet' : [None],
                        'private_ip' : [None],
                        'private_ip_allocation' : [None],
                        'internalDomainNameSuffix' : [None],
                        'macAddress' : [None],
                        'public_ip' : [None],
                        'public_ip_allocation' : [None],
                        'fqdn' : [None],
                        'CPUsAvailable': [None],
                        'CPUsPerCore': [None],
                        'Memory' : [None],
                        'osdisk_size' : ['properties', 'storageProfile', 'osDisk', 'diskSizeGB'],
                        'TOTAL_ADDITIONAL_DATA_DISKS' : [None],
                        'SUM_ADDITIONAL_DATA_DISKS_SIZE' : [None],
                        'dxcManaged' : ['tags', 'dxcManaged'],
                        'dxcMonitored' : ['tags', 'dxcMonitored'],
                        'dxcConfigurationCheck' : ['tags', 'dxcConfigurationCheck'],
                        'dxcBackup' : ['tags', 'dxcBackup'],
                        'dxcPatchSchedule' : ['tags', 'dxcPatchSchedule'],
                        'dxcEPAgent' : ['tags', 'dxcEPAgent'],
                        'dxcPatchGroup' : ['tags', 'dxcPatchGroup'],
                        'dxcPrimarySupport' : ['tags', 'dxcPrimarySupport'],
                        'DXCAuditVMDeployTag' : ['tags', 'DXCAuditVMDeployTag'],
                        'dxcAutoShutdownSchedule' : ['tags', 'dxcAutoShutdownSchedule'],
                        'LAST_LOADED' : [None],
                        'network_interface_id' : ['properties', 'networkProfile', 'networkInterfaces', 0, 'id'],
                        'manageddiskid' : ['properties', 'storageProfile', 'osDisk', 'managedDisk', 'id'],
                        'dataDisks' : ['properties', 'storageProfile', 'dataDisks']
                    }
                
                logger.info(f"Starting to Proccess the VM data for all VMs for Subscription: {subscription_name}")
                temp=[]
                try:
                    for vm in vms_response['value']:
                        vm_data = {}
                        for attribute, access_chain in vm_attributes.items():
                            try:
                                value = vm
                                for item in access_chain:
                                    if item == 'split':
                                        index = access_chain.index('split')
                                        split_value = access_chain[index + 1]
                                        value = value.split(split_value)[access_chain[index + 2]]
                                        break
                                    elif item is None:
                                        value=None
                                    elif item == 'tags':
                                        value=value[item].get(access_chain[1])
                                        break
                                    else:
                                        value = value[item]
                                vm_data[attribute] = value
                            except (KeyError, TypeError, IndexError):
                                vm_data[attribute] = None

                        vm_data['subscription_id']=subscription_id
                        vm_data['subscription_name']=subscription_name
                        vm_data['LAST_LOADED']=last_loaded

                        # Get network interface details for the VM
                        network_interface_id = vm_data.get('network_interface_id')
                        network_interface = network_interfaces.get(network_interface_id)

                        nw_attributes={
                            'public_ip_allocation' : ['properties', 'publicIPAllocationMethod'],
                            'public_ip': ['properties', 'ipAddress'], 
                            'fqdn': ['properties', 'dnsSettings', 'fqdn']
                        }
                        
                        # Mapping the Public Network details for the VM
                        if network_interface:
                            for attribute, access_chain in nw_attributes.items():
                                try:
                                    value = network_interface
                                    for item in access_chain:
                                        value = value[item]
                                    vm_data[attribute] = value
                                except (KeyError, TypeError, IndexError):
                                    vm_data[attribute] = None

                        # mapping private network related information
                        matching_pvt_nws_items = [item for item in pvt_nw_response['value'] if vm_data['network_interface_id'].upper() in item['id'].upper()]
                        if matching_pvt_nws_items:
                            vm_data['private_ip'] = matching_pvt_nws_items[0]['properties']['ipConfigurations'][0]['properties']['privateIPAddress']
                            vm_data['private_ip_allocation'] = matching_pvt_nws_items[0]['properties']['ipConfigurations'][0]['properties']['privateIPAllocationMethod']
                            vm_data['subnet_id'] = matching_pvt_nws_items[0]['properties']['ipConfigurations'][0]['properties']['subnet']['id']
                            vm_data['internalDomainNameSuffix'] = matching_pvt_nws_items[0]['properties']['dnsSettings'].get('internalDomainNameSuffix')
                            vm_data['macAddress'] = matching_pvt_nws_items[0]['properties']['macAddress']
                            nw_security_group = matching_pvt_nws_items[0]['properties'].get('networkSecurityGroup')
                            if nw_security_group is not None:
                                vm_data['networkSecurityGroup'] = nw_security_group.get('id').split('/')[8]
                            pvt_nw_response['value'].remove(matching_pvt_nws_items[0])

                        # mapping CPU, Memory & Architecture information
                        key=(vm_data['vmsize']+"_"+vm_data["location"]).upper()
                        if key in vm_specs:
                            try:
                                vm_data['Memory']=vm_specs[key].get('MemoryGB')
                                vm_data['CPUsAvailable']=vm_specs[key].get('vCPUsAvailable')
                                vm_data['CPUsPerCore']=vm_specs[key].get('vCPUsPerCore')
                                vm_data['CpuArchitectureType']=vm_specs[key].get('CpuArchitectureType')
                            except:
                                logger.debug(f"Problem getting the SKU Data (CPU, Memory, Architecture) for VM_ID: '{vm_data['vm_id']}'")

                        # Mapping the VM Status
                        matching_vm_id_items = [item for item in vms_status_response['value'] if vm_data['vm_id'].upper() in item['properties']['vmId'].upper()]
                        if matching_vm_id_items:
                            try:
                                vm_data['vm_status'] = matching_vm_id_items[0]['properties']['instanceView']['statuses'][1]['displayStatus']
                                vms_status_response['value'].remove(matching_vm_id_items[0])
                            except:
                                vm_data['vm_status'] : None
                                logger.debug(f"Problem getting the VM Status for VM_ID: '{vm_data['vm_id']}'")
                        
                        # Mapping the default disksize available in VM_ENDPOINT API Call 
                        matching_disksize_items = [item for item in disksize_response['value'] if vm_data['manageddiskid'] is not None and vm_data['manageddiskid'].upper() in item['id'].upper()]
                        if matching_disksize_items:
                            try:
                                vm_data['osdisk_size'] = matching_disksize_items[0]['properties']['diskSizeGB']
                                disksize_response['value'].remove(matching_disksize_items[0])
                            except:
                                logger.debug(f"Problem getting the OS_disk_Size for VM_ID: '{vm_data['vm_id']}'")
                        
                        # Mapping the additional data disks(if any) attached to a vm along with it's size
                        disk_size={}
                        if len(vm_data['dataDisks']) > 0:
                            for index, value in enumerate(vm_data['dataDisks']):
                                matching_disksize_items = [item for item in disksize_response['value'] if (value.get('managedDisk').get('id')).upper() is not None and (value.get('managedDisk').get('id')).upper() in item['id'].upper()]
                                if matching_disksize_items:
                                    try:
                                        disk_size[f'data_disk_{index+1}'] = matching_disksize_items[0]['properties']['diskSizeGB']
                                        disksize_response['value'].remove(matching_disksize_items[0])
                                    except:
                                        logger.debug(f"Problem getting the Additional Data Disk for VM_ID: '{vm_data['vm_id']}'")
                        
                        disk_sum=0
                        for value in disk_size.values():
                            disk_sum+=int(value)
                        
                        vm_data['TOTAL_ADDITIONAL_DATA_DISKS']=str(len(disk_size))
                        vm_data['SUM_ADDITIONAL_DATA_DISKS_SIZE']=str(disk_sum)
                        
                        #Mapping Subnet for the vm
                        subnet_id = vm_data['subnet_id']
                        try:
                            for item in subnets:
                                if vm_data['subnet'] is not None:
                                    break
                                subnet = item['properties']['subnets']
                                if subnet is not None:
                                    for d in subnet:
                                        if subnet_id in d['id']:
                                            vm_data['subnet'] = d['properties']['addressPrefix']
                                            break
                        except:
                            logger.debug(f"Problem getting the Additional Data Disk for VM_ID: '{vm_data['vm_id']}'")

                        # Poping unwanted information from the dictionary so as to have only the required data at the destination(csv/DB)
                        vm_data['subnet_id'] = matching_pvt_nws_items[0]['properties']['ipConfigurations'][0]['properties']['subnet']['id'].split('/')[10]
                        vm_data.pop('network_interface_id', None)
                        vm_data.pop('manageddiskid', None)
                        vm_data.pop('dataDisks', None)
                        # vm_details.append(vm_data)
                        temp.append(vm_data)
                    logger.info(f"Successfully Processed the VM data for all VMs for Subscription: {subscription_name}")
                
                    async def get_instance_view(vm, headers):
                        INSTANCE_VIEW_ENDPOINT = "https://management.azure.com/subscriptions/{subscription_id}/resourceGroups/{resource_group}/providers/Microsoft.Compute/virtualMachines/{vm_name}/instanceView?api-version=2023-03-01"
                        subscription_id = vm.get('subscription_id')
                        resource_group = vm.get("resource_group")
                        vm_name = vm.get("vm_name")

                        async def retry_request(url, headers, retries=3):
                            try:
                                async with aiohttp.ClientSession(headers=headers) as session:
                                    async with session.get(url) as response:
                                        return await response.json()
                            except:
                                if retries > 0:
                                    await asyncio.sleep(1)
                                    return await retry_request(url, headers, retries - 1)
                                else:
                                    logger.error(f"Max Retries Exceeded During Instance View API Call for URL: {url}")
                                    logger.error("Traceback:\n%s", traceback.format_exc())

                        url = INSTANCE_VIEW_ENDPOINT.format(subscription_id=subscription_id, resource_group=resource_group, vm_name=vm_name)
                        response = await retry_request(url, headers)
                        return response

                    async def process_vm(vm, headers, semaphore):
                        async with semaphore:
                            try:
                                ins_view_response = await get_instance_view(vm, headers)
                                resourceutil()
                                vm['ins_OS_Name'] = ins_view_response.get("osName")
                                vm['ins_OS_Version'] = ins_view_response.get("osVersion")
                                vm['vmAgentVersion'] = ins_view_response.get("vmAgent", {}).get("vmAgentVersion")
                                vm['vmAgent_code'] = ins_view_response.get("vmAgent", {}).get("statuses", [{}])[0].get("code", "").split("/")[1]
                                vm['vmAgent_status'] = ins_view_response.get("vmAgent", {}).get("statuses", [{}])[0].get("displayStatus")
                                vm['vmAgent_message'] = ins_view_response.get("vmAgent", {}).get("statuses", [{}])[0].get("message")
                            except:
                                logger.error(f"Problem getting the Instance View Data for VM_ID: '{vm['vm_id']}', VM_STATUS={vm['vm_status']}")
                                logger.error("Traceback:\n%s", traceback.format_exc())

                    semaphore = asyncio.Semaphore(20)
                    tasks = []

                    for vm in temp:
                        if vm.get('vm_status') != 'VM deallocated':
                            task = asyncio.create_task(process_vm(vm, headers, semaphore))
                            tasks.append(task)

                    await asyncio.gather(*tasks)
                    resourceutil()

                    for vm in temp:
                        vm_details.append(vm)
                except:
                    logger.error(f"Problem Processing the VM data for all VMs for Subscription: {subscription_name}")
                    logger.error("Traceback:\n%s", traceback.format_exc())
                    logger.warning("Continuing Program Execution for Remaining Subscriptions in the Scope")
        else:
            logger.error(f"Failed Getting the Access Token Skipping the Subscription: {subscription_name}")

    # Start the event loop and process customers concurrently
    logger.info("Starting concurrent processing of all customers")
    await asyncio.gather(*(process_customer(customer, semaphore) for customer in scope))
    resourceutil()
    logger.info("Finished processing of all the customers")

    return vm_details

def push_to_db(vm_details):
    logger.debug("Inside of push_to_db function()")
    dbtime = datetime.datetime.now().timestamp()
    # Below DB Logic will update only the column that has
    # a NOT NULL value
    try:
        k=get_db_connection()
        resourceutil()
        # connection = k.con
        connection = k
        cursor = k.cursor()
        # connection = cx_Oracle.connect('john', 'admin', 'localhost:1521/xe')
        # cursor = connection.cursor()
        db={}
        for vm_dict in vm_details:
            insert_statement=""
            values_statement=""
            update_statement=""
            for key in vm_dict.keys():
                # Creating Update statement
                if key != 'vm_id' and vm_dict.get(key) is not None:
                    if key == 'VM_Creation_Date' or key == 'LAST_LOADED':
                        update_statement=update_statement + (f"{key} = TO_DATE(:{key}, 'YYYY-MM-DD')") + ","
                    else:
                        update_statement=update_statement + (f"{key} = :{key}") + ","

                # Creating values statement
                if key == 'VM_Creation_Date' or key == 'LAST_LOADED':
                    values_statement=values_statement + f"TO_DATE(:{key}, 'YYYY-MM-DD'),"
                else:
                    values_statement=values_statement + f":{key},"

                # Creating insert statement
                insert_statement=insert_statement + f"{key},"

            values_statement = values_statement[:-1]
            update_statement = update_statement[:-1]
            insert_statement = insert_statement[:-1]
            merge_query = f"""MERGE INTO john.azure_ci_import t
                USING (SELECT 1 FROM dual) dummy
                ON (t.vm_id = :vm_id)
                WHEN MATCHED THEN
                    UPDATE SET {update_statement}
                WHEN NOT MATCHED THEN
                    INSERT ({insert_statement})
                VALUES ({values_statement})"""
            
            # Updating the records dictionary to process it for DB transaction using executemany method
            if merge_query not in db.keys():
                db[merge_query]=[]
                db[merge_query].append(vm_dict)
            else:
                db[merge_query].append(vm_dict)
        
        logger.info("Trying to update to data to the database")
        for key, value in db.items():
            try:
                cursor.executemany(key, value)
                resourceutil()
            except:
                logger.error(f"Encountered an Error while updating data to Database")
                logger.error("Traceback:\n%s", traceback.format_exc())

        logger.info("Data Updated Successfully in the Database")
        connection.commit()
        cursor.close()
        connection.close()
        resourceutil()
        return int(datetime.datetime.now().timestamp() - dbtime)
    except:
        logger.error("Could not establish the connection with the Database... cannot update data to the database")
        logger.error("Traceback:\n%s", traceback.format_exc())

def main(args):
    logger.debug("Inside the main() function")
    start_time = datetime.datetime.now().timestamp()
    # check if script was ran for a single customer or not
    subscription_id=args.subscription_id
    # collect vm_data for all the specified scope
    vm_data=asyncio.run(get_vm_details(subscription_id))
    resourceutil()
    # finally upsert to DB
    runmode=args.test
    if not runmode:
        db_time=push_to_db(vm_data)
        resourceutil()
    global db_con_time
    logger.info(f"Total Execution Time: {int(datetime.datetime.now().timestamp() - start_time)} Seconds")
    logger.info(f"Azure Execution Time: {int(datetime.datetime.now().timestamp() - start_time) - db_time - db_con_time} Seconds")
    logger.info(f"Time Elapsed in Obtaining Database Connection: {db_con_time} Seconds")
    logger.info(f"Databse Data Updation Time: {db_time} Seconds")

if __name__ == "__main__":
    logger=setup_logging(args)
    resourceutil()
    runmode=args.test
    if runmode:
        logger.info("Running the script in the TEST Mode, Changes will not be comitted to the database")
    else:
        logger.warning("!! ATTENTION !! - Running the script in the NON-TEST Mode, CHANGES WILL BE COMMITTED TO THE DATABASE. If you are on Linux System Press 'CTRL+Z' to Freeze Execution")
    
    # Even if verbose or debug mode is not selected while running the script
    # user gets notified that changes will be commited to the database
    if not args.debug and not args.verbose:
        print("!! ATTENTION !! - Running the script in the NON-TEST Mode, CHANGES WILL BE COMMITTED TO THE DATABASE. If you are on Linux System Press 'CTRL+Z' to Freeze Execution")
    
    logger.debug("Starting to Execute the main function")
    main(args)
    resourceutil()

    logger.info(f"AVG CPU: {int(statistics.mean(cpu))}%    AVG MEM: {int(statistics.mean(mem))} MB")
    logger.info(f"MAX CPU: {int(max(cpu))}%     MAX MEM: {int(max(mem))} MB")