#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
Ansible module to manage A10 Networks objects
(c) 2017, Fadi Hafez <fhafez@a10networks.com>

This file is part of Ansible

Ansible is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Ansible is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Ansible.  If not, see <http://www.gnu.org/licenses/>.
"""

DOCUMENTATION = '''
---
module: a10_ssl_v3
version_added: "2.1"
short_description: Manage A10 Networks AX/SoftAX/Thunder/vThunder devices
description:
    - Manage extended SSL objects on A10 Networks devices via aXAPI
author: "Fadi Hafez (@a10-fhafez)"
notes:
    - Requires A10 Networks aXAPI 3.0
options:
  host:
    description:
      - hostname or ip of your A10 Networks device
    required: true
  username:
    description:
      - admin account of your A10 Networks device
    required: true
    aliases: ['user', 'admin']
  password:
    description:
      - admin password of your A10 Networks device
    required: true
    aliases: ['pass', 'pwd']
  partition:
    description:
      - L3V partition to upload/download/delete the certificate from/to.  Will be added to 'shared' if not specified
    required: false
    default: null
    choices: []
  state:
    description:
      - create or remove SSL Cert
    required: false
    default: present
    choices: ['present', 'absent']
  file_name:
    description:
      - SSL cert/key to upload/download in PEM format. 
        If uploading separate certiticate and key then .pem file must be in the local directory.
        When downloading Certificate, key or combination of both will be downloaded into the local directory.
        If uploading a combination certificate and key then they must be tar gzipped in a directory structure where the key 
        goes into the /key directory and the certificate goes into the /cert directory 
    required: false
    aliases: ['filename']
  cert_key_name:
    description:
      - SSL cert/key name.
        Used when uploading a certificate/key combination to distinguish between the filename and the certificate/key names
    required: false
    aliases: ['cert_key_name']
  file_type:
    description:
      - file type
    required: false
    choices: ['certificate','key','certificate/key']
  method:
    description:
      - One of 'upload', 'download'
        only applicable when state == present
    required: false
    default: null
    choices: ['upload','download']
  overwrite:
    description:
      - If the cert is found, should you overwrite or just ignore it
        only applicable when state == present
    required: false
    default: 'no'
    choices: ['yes', 'no']
  validate_certs:
    description:
      - If C(no), SSL certificates will not be validated. This should only be used
        on personally controlled devices using self-signed certificates.
    required: false
    version_added: 2.2
    default: 'yes'
    choices: ['yes', 'no']

'''

EXAMPLES = '''
# Upload an SSL Cert/Key combination
- a10_ssl: 
    host: a10.mydomain.com
    username: myadmin
    password: mypassword
    partition: PART_A
    file_name: mycert.tar.gz
    file_type: certificate/key
    cert_key_name: akeycert
    method: upload
    overwrite: yes
    
# Upload an SSL Cert Key only
- a10_ssl: 
    host: a10.mydomain.com
    username: myadmin
    password: mypassword
    partition: PART_A
    file_name: mycert.pem
    file_type: certificate
    cert_key_name: ""
    method: upload
    overwrite: yes

'''

RETURN = ''' # '''

CLRF = '\r\n'
Empty = ''

def clrf(writer, should):
    if should is True:
        writer.write(CLRF)

def saveFile(filename, data):

    try:
        f = open(filename, 'wb')
        try:
            f.write(data)
        finally:
            f.close()
    except Exception, e:
        raise e

# 

def writeFile(name, filename, json_body, pfx_passwd, body, boundary, writer, needsCLRF):
    clrf(writer, needsCLRF)
    block = [boundary, 
        'Content-Disposition: form-data; name="json"; filename="blob"',
        'Content-Type: application/json'  + CLRF,
#        '{"ssl-cert": { "certificate-type": "pem", "action": "import", "file": "%s", "file-handle": "%s"}}' % (filename, filename),
#        '{"ssl-key": {"action": "import", "file": "%s", "file-handle": "%s", "dst-file":"%s"}}' % (filename, filename, filename),   
        json_body,
        boundary,
        'Content-Disposition: form-data; name="Content-Type: application/x-gzip;file"; filename="%s"' % filename,
#        'Content-Disposition: form-data; name="file"; filename="%s"' % filename,
        'Content-Type: application/octet-stream'  + CLRF]
    writer.write(CLRF.join(block))
    writer.write(CLRF)
    writer.write(body)
#    writer.write(CLRF)


def buildPayload(filename, pfx_passwd, json_body):
    header_boundary = '--' + mimetools.choose_boundary()
    field_boundary = '--' + header_boundary
    payload = io.BytesIO()
    needsCLRF = False
    try:
        f = open(filename, 'rb')
        try:
            data = f.read()
            writeFile("upload", filename, json_body, pfx_passwd, data, field_boundary, payload, needsCLRF)
        finally:
            f.close()
    except Exception, e:
        raise e
    payload.write(CLRF + field_boundary + '--' + CLRF)
    return header_boundary,payload.getvalue()


def uploadSSL(url, name, cert_type, pfx_passwd, filepath, json_body, signature):
    boundary,data = buildPayload(filepath, pfx_passwd, json_body)
    response = None
    try:
        response = open_url(url, data, 
            {
                'Content-Type' : 'multipart/form-data; boundary=%s' % boundary, 
                'Authorization': 'A10 %s' % signature,
                'X-Requested-By' : 'ansible', 
                'User-Agent': 'ansible', 
                'Accept':'*/*'
            },
            validate_certs=False,
            method='POST')
        changed = response.getcode() == 200
    except Exception, e:
        e.args += (response,)
        raise e

    return changed, response.getcode()


def main():
    argument_spec = a10_argument_spec()
    argument_spec.update(url_argument_spec())
    argument_spec.update(
        dict(
            state=dict(type='str', default='present', choices=['present', 'absent']),
            partition=dict(type='str', aliases=['partition','part'], required=False),
            file_name=dict(type='str', aliases=['filename'], required=False),
            cert_key_name=dict(type='str', required=False),
            file_type=dict(type='str', choices=['key','certificate','certificate/key'], required=False, default='certificate'),
            pfx_passwd=dict(type='str', required=False),
            method=dict(type='str', choices=['upload','download'], required=False),
            overwrite=dict(type='bool', default=False, required=False),
        )
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=False
    )

    host = module.params['host']
    username = module.params['username']
    password = module.params['password']
    part = module.params['partition']
    state = module.params['state']
    file_name = module.params['file_name']
    cert_key_name = module.params['cert_key_name']
    file_type = module.params['file_type']
    pfx_passwd = module.params['pfx_passwd']
    method = module.params['method']
    overwrite = module.params['overwrite']

  
    if method and method != 'upload' and method != 'download':
        module.fail_json(msg="method must be one of 'upload' or 'download'")

    # authenticate
    axapi_base_url = 'http://%s/axapi/v3/' % host
    signature = axapi_authenticate_v3(module, axapi_base_url + 'auth', username, password)
    json_body = {}
    
    if file_type == "certificate":
        ext_url = 'ssl-cert'
        json_body = {"ssl-cert": { "certificate-type": "pem", "action": "import", "file": file_name, "file-handle": file_name}}
    elif file_type == "key":
        ext_url = 'ssl-key'
        json_body = {"ssl-key": {"action": "import", "file": file_name, "file-handle": file_name, "dst-file":file_name}}
    elif file_type == "certificate/key":
        ext_url = 'ssl-cert-key'
        
        # NOT WORKING YET
        # need to upload a .tar.gz file containing the key and cert
        json_body_search = {"ssl-cert-key": {"action": "check", "file": cert_key_name, "file-handle": cert_key_name}}
        
        if method == "upload":
            json_body = {"ssl-cert-key": {"action": "import", "file": file_name, "file-handle": file_name}}
        elif method == "download":
            json_body = {"ssl-cert-key": {"action": "export", "file": file_name, "file-handle": file_name, "dst-file": "blahdoo"}}
            
    
    # change partitions if we need to
    if part:
        part_change_result = axapi_call_v3(module, axapi_base_url + 'active-partition/' + part, method="POST", signature=signature, body="")
        if (part_change_result['response']['status'] == 'fail'):
            # log out of the session nicely and exit with an error
            result = axapi_call_v3(module, axapi_base_url + 'logoff', method="POST", signature=signature, body="")
            module.fail_json(msg=part_change_result['response']['err']['msg'])

    # clear the 'changed' flag
    changed = False
    msg = ""
    
    # does the cert exist on the device already
    cert_found_on_device = False

    # check if the SSL cert/key exists on the device
    # for a cert/key we need to issue a POST and not a GET
    if file_type == "certificate/key":
        
        # result = axapi_call_v3(module, axapi_base_url + 'file/' + ext_url, method="POST", body=json_body_search, signature=signature)
        
        # there is no way to check for key/cert together so we must make two separate calls to validate        
        result_cert_lookup = axapi_call_v3(module, axapi_base_url + 'file/ssl-cert/' + cert_key_name, method="GET", signature=signature)
        result_key_lookup = axapi_call_v3(module, axapi_base_url + 'file/ssl-key/' + cert_key_name, method="GET", signature=signature)
        
        if ('response' in result_cert_lookup and result_cert_lookup['response']['status'] == 'fail' and (result_cert_lookup['response']['code'] == 404 or result_cert_lookup['response']['code'] == 400) or \
            'response' in result_key_lookup and result_key_lookup['response']['status'] == 'fail' and (result_key_lookup['response']['code'] == 404 or result_key_lookup['response']['code'] == 400)):
            cert_found_on_device = False
        elif 'response' in result_cert_lookup and result_cert_lookup['response']['status'] == 'fail' and result_cert_lookup['response']['code'] != 404 and result_cert_lookup['response']['code'] != 400:
                logoff_result = axapi_call_v3(module, axapi_base_url + 'logoff', method="POST", signature=signature, body="")
                module.fail_json(msg=result['response']['err']['msg'])
        elif 'response' in result_cert_lookup and result_cert_lookup['response']['status'] == 'fail' and result_key_lookup['response']['code'] != 404 and result_key_lookup['response']['code'] != 400:
                logoff_result = axapi_call_v3(module, axapi_base_url + 'logoff', method="POST", signature=signature, body="")
                module.fail_json(msg=result['response']['err']['msg'])            
        else:
            cert_found_on_device = True
        
        # file_name = "bundle.tar.gz"
    else:
        result = axapi_call_v3(module, axapi_base_url + 'file/' + ext_url + '/' + file_name, method="GET", signature=signature)
    
        if ('response' in result and result['response']['status'] == 'fail'):
            if (result['response']['code'] == 404 or result['response']['code'] == 400):
                cert_found_on_device = False
            else:
                logoff_result = axapi_call_v3(module, axapi_base_url + 'logoff', method="POST", signature=signature, body="")
                module.fail_json(msg=result['response']['err']['msg'])
        else:
            cert_content = result['response']['data']
            cert_found_on_device = True

    if state == 'present':

        # adding the SSL cert        
        if (method == "upload" and cert_found_on_device and overwrite) or \
        (method == "upload" and not cert_found_on_device):
                        
            # make sure the file being uploaded exists locally
            if os.path.isfile(file_name) is False:
                # log out of the session nicely and exit with an error
                logoff_result = axapi_call_v3(module, axapi_base_url + 'logoff', method="POST", signature=signature, body="")
                module.fail_json(msg='File not found ' + file_name)
            else:
                try:
                    result = uploadSSL(axapi_base_url + 'file/' + ext_url, 'upload', file_type, pfx_passwd, file_name, json.dumps(json_body), signature=signature)
                except Exception, e:
                    # log out of the session nicely and exit with an error
                    #err_result = e['changed']
                    logoff_result = axapi_call_v3(module, axapi_base_url + 'logoff', method="POST", signature=signature, body="")
                    module.fail_json(msg=e)

            if axapi_failure(result):
                # log out of the session nicely and exit with an error
                logoff_result = axapi_call_v3(module, axapi_base_url + 'logoff', method="POST", signature=signature, body="")
                module.fail_json(msg="failed to upload the cert: %s" % result['response']['err']['msg'])

            changed = True
            
        elif method == "download" and (cert_found_on_device or file_type == "certificate/key"):
            saveFile(file_name, cert_content)
            
        elif method == "download" and not cert_found_on_device:
            module.fail_json(msg="cert not found")
            
        elif cert_found_on_device and not overwrite:
            msg = "certificate/key found on device and not overwritten"

    elif state == 'absent':
        # removal of SSL cert
        
        if cert_found_on_device:
            
            if file_type == 'certificate':
                result = axapi_call_v3(module, 'https://%s/axapi/v3/pki/delete' % host, method="POST", signature=signature, body={"delete": {"cert-name": file_name}})
            elif file_type == 'key':
                result = axapi_call_v3(module, 'https://%s/axapi/v3/pki/delete' % host, method="POST", signature=signature, body={"delete": {"private-key": file_name}})
            else:
                # two calls have to be made to delete the private key and the public key
                result = axapi_call_v3(module, 'https://%s/axapi/v3/pki/delete' % host, method="POST", signature=signature, body={"delete": {"cert-name": cert_key_name}})

                if ('response' in result and result['response']['status'] == 'fail'):
                    # log out of the session nicely and exit with an error
                    logoff_result = axapi_call_v3(module, axapi_base_url + 'logoff', method="POST", signature=signature, body="")
                    module.fail_json(msg=result['response']['err']['msg'])
                else:
                    changed = True

                result = axapi_call_v3(module, 'https://%s/axapi/v3/pki/delete' % host, method="POST", signature=signature, body={"delete": {"private-key": cert_key_name}})

                    
            if ('response' in result and result['response']['status'] == 'fail'):
                # log out of the session nicely and exit with an error
                logoff_result = axapi_call_v3(module, axapi_base_url + 'logoff', method="POST", signature=signature, body="")
                module.fail_json(msg=result['response']['err']['msg'])
            else:
                changed = True
                
        else:
            result = axapi_call_v3(module, axapi_base_url + 'logoff', method="POST", signature=signature, body="")
            module.fail_json(msg="ssl cert not found on device")            

    # log out of the session nicely and exit
    result = axapi_call_v3(module, axapi_base_url + 'logoff', method="POST", signature=signature, body="")
    module.exit_json(changed=changed, content=result, msg=msg)

# standard ansible module imports
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.urls import url_argument_spec
from ansible.module_utils.a10 import axapi_call, axapi_call_v3, a10_argument_spec, axapi_authenticate_v3, axapi_enabled_disabled
import mimetools
import mimetypes
import io

if __name__ == '__main__':
    main()
