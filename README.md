# bluecat-api-v2-public

```
Setup:
These scripts use enviroment variables.  To start, copy the file to somewhere safe, like ~/.ssh/ in linux (use any filename you like):
    filename=~/.ssh/bluecat.env
    cp bluecat.example.env $filename
Set the permissions to owner only:
    chmod 600 $filename
Then edit the file and fill in the server name, user name, password, Configuration name, and View name.
Source the file to set the environment variables:
    source $filename

There are a few directories here:    
    curl - Simple bash scripts using curl to illustrate the steps, and for testing.
    python - Better scripts with lots of options built in.
		The python scripts need the "requests" module installed.
```

Here are some typical commands:

# Add DHCP Reserved

`add_dhcp_reserved.py` is a script designed to link an address with a macAddress and assign DHCP_RESERVED state to it.
 The script supports two modes of input: via a file or directly through command line arguments.

### 1. File Input Mode

In this mode, the script reads a file that follows the specified format.

**Command:**
```
add_dhcp_reserved.py [--server servername (optional)] -f <filename>
```

**Example:**
```
add_dhcp_reserved.py -f input.txt
```
**Format:**
When using the file input mode, each line in the specified file should follow this format:

```
<ip_address>,<mac_address>,<hostname>(optional)
```
**Example:**
```
192.168.1.101,00:1B:2C:3D:4E:5F,"ExampleHost"
192.168.1.102,00:1C:2D:3E:4F:5G
```

### 2. Direct Input Mode

In this mode, the script accepts details directly through command line arguments. This is useful for adding DHCP_RESER
VED for a single address quickly.

**Command:**
```
add_dhcp_reserved.py --ip IP --mac MAC --ipname DESC --hostname NAME --view VIEW
```

**Example:**
```
add_dhcp_reserved.py --ip 192.168.1.100 --mac 00:1A:2B:3C:4D:5E --ipname "ExampleName" --hostname "ExampleHost" --view
 "Internal"
```



# BlueCat Address Manager v2 REST CLI

`bamv2api.py` is a command-line interface (CLI) that provides a way to interact with BAM v2 REST API. The tool support
s GET, POST, PUT, DELETE, and PATCH menthods to manage resources within BAM.

### Usage

- `--method`, `-m`: The HTTP method to use (default: GET). Supported methods: GET, POST, PUT, DELETE, PATCH.
- `--data`: The data body to send with POST, PUT, PATCH requests (in JSON format).
- `--args`: Additional arguments to be sent as query parameters in the format name=value.

### Examples

1. **GET Request**
```
./bamv2api.py groups/124/users -m GET 
```
```
./bamv2api.py groups/124/users -m GET --args filter="name:eq('exampleuser')" fields=name
```

2. **POST Request**
```
./bamv2api.py groups -m POST --data '{"name": "newGroup"}' 
```

3. **PUT Request**
```
./bamv2api.py groups/124 -m PUT --data '{"description": "Updated description"}' 
```

4. **DELETE Request**
```
./bamv2api.py groups/124 -m DELETE 
```

5. **PATCH Request**
```
./bamv2api.py groups/124 -m PATCH --data '{"description": "Patched description"}' 
```

