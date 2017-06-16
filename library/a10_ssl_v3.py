#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
Ansible module to manage A10 Networks objects
(c) 2016, Fadi Hafez <fhafez@a10networks.com>

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
module: a10_ssl
version_added: 1.8
short_description: Manage A10 Networks AX/SoftAX/Thunder/vThunder devices
description:
    - Manage extended SSL objects on A10 Networks devices via aXAPI
author: Fadi Hafez using works of Mischa Peters
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
      - SSL cert/key to upload/download in PEM format
        certiticate must be in the local directory when uploading
        certificate will be downloaded into the local directory
    required: false
    aliases: ['filename']
  file_type:
    description:
      - file type
    required: false
    choices: ['certificate','key']
  method:
    description:
      - One of 'upload', 'download'
        only applicable when state == present
    required: false
    default: null
    choices: ['upload','download']
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
# Upload an SSL Cert
- a10_ssl: 
    host: a10.mydomain.com
    username: myadmin
    password: mypassword
    partition: PART_A
    file_name: mycert.crt.pem
    file_type: certificate
    method: upload
'''

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

   
def writeFile(name, filename, pfx_passwd, body, boundary, writer, needsCLRF):
    clrf(writer, needsCLRF)
    block = [boundary, 
        'Content-Disposition: form-data; name="json"; filename="blob"',
        'Content-Type: application/json'  + CLRF,
        '{"ssl-cert": { "certificate-type": "pem", "action": "import", "file": "A10_test.pem", "file-handle": "%s"}}' % (filename), 
        boundary,
        'Content-Disposition: form-data; name="file"; filename="%s"' % filename,
        'Content-Type: application/octet-stream'  + CLRF]
    writer.write(CLRF.join(block))
    writer.write(CLRF)
    writer.write(body)
    writer.write(CLRF)


def buildPayload(filename, pfx_passwd):
    header_boundary = '--' + mimetools.choose_boundary()
    field_boundary = '--' + header_boundary
    payload = io.BytesIO()
    needsCLRF = False
    try:
        f = open(filename, 'rb')
        try:
            data = f.read()
            writeFile("upload", filename, pfx_passwd, data, field_boundary, payload, needsCLRF)
        finally:
            f.close()
    except Exception, e:
        raise e
    payload.write(CLRF + field_boundary + '--' + CLRF)
    return header_boundary,payload.getvalue()


def uploadSSL(url, name, cert_type, pfx_passwd, filepath, signature):
    boundary,data = buildPayload(filepath, pfx_passwd)
    response = None
    
    certname = filepath.split('/')[-1]
    
    files = [('json', ('blob', jdata, 'application/json')), 
             ('file', (certname, open(filepath, 'rb'), 'application/octet-stream'))]
    
    plist = aXAPI_ULFile("http://" + AXIP + apath, session_id, files)
    
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
            file_type=dict(type='str', required=False),
            pfx_passwd=dict(type='str', required=False),
            method=dict(type='str', choices=['upload','download'], required=False),
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
    file_type = module.params['file_type']
    pfx_passwd = module.params['pfx_passwd']
    method = module.params['method']

  
    if method and method != 'upload' and method != 'download':
        module.fail_json(msg="method must be one of 'upload' or 'download'")

    # authenticate
    axapi_base_url = 'http://%s/axapi/v3/' % host
    signature = axapi_authenticate_v3(module, axapi_base_url + 'auth', username, password)

    # change partitions if we need to
    if part:
        result = axapi_call_v3(module, axapi_base_url + 'active-partition/' + part, method="POST", signature=signature, body="")
        if (result['response']['status'] == 'fail'):
            # log out of the session nicely and exit with an error
            result = axapi_call_v3(module, axapi_base_url + 'logoff', method="POST", signature=signature, body="")
            module.fail_json(msg=result['response']['err']['msg'])

    changed = False
    if state == 'present':

        if method == "upload":

            if os.path.isfile(file_name) is False:
                # log out of the session nicely and exit with an error
                result = axapi_call_v3(module, axapi_base_url + 'logoff', method="POST", signature=signature, body="")
                module.fail_json(msg='File does not exist')
            else:
                try:
                    result = uploadSSL(axapi_base_url + 'file/ssl-cert', 'upload', file_type, pfx_passwd, file_name, signature=signature)
                except Exception, e:
                    # log out of the session nicely and exit with an error
                    #err_result = e['changed']
                    result = axapi_call_v3(module, axapi_base_url + 'logoff', method="POST", signature=signature, body="")
                    module.fail_json(msg=e)

            if axapi_failure(result):
                # log out of the session nicely and exit with an error
                result = axapi_call_v3(module, axapi_base_url + 'logoff', method="POST", signature=signature, body="")
                module.fail_json(msg="failed to upload the cert: %s" % result['response']['err']['msg'])

            changed = True
            
            
        elif method == "download":

            result = axapi_call_v3(module, axapi_base_url + 'file/ssl-cert/' + file_name, method="GET", signature=signature)
            if ('response' in result and result['response']['status'] == 'fail' and 'failed' in result['response']['err']['msg']):
                # log out of the session nicely and exit with an error
                result = axapi_call_v3(module, axapi_base_url + 'logoff', method="POST", signature=signature, body="")
                module.fail_json(msg=result['response']['err']['msg'])
            else:
                saveFile(file_name, result['response']['err']['msg'])
            

        if method == "upload":
            changed = True

    elif state == 'absent':
        
        
        # does the SSL Cert exist on the load balancer
        result = axapi_call_v3(module, axapi_base_url + 'file/ssl-cert/' + file_name, method="GET", signature=signature)
        if ('response' in result and result['response']['status'] == 'fail' and 'failed' in result['response']['err']['msg']):
            # log out of the session nicely and exit with an error
            result = axapi_call_v3(module, axapi_base_url + 'logoff', method="POST", signature=signature, body="")
            module.fail_json(msg=result['response']['err']['msg'])

        result = axapi_call_v3(module, axapi_base_url + 'file/ssl-cert', method="POST", signature=signature, body='{"ssl-cert": {"file": "%s", "file-handle": "%s", "action":"delete"}}')
        if ('response' in result and result['response']['status'] == 'fail'):
            # log out of the session nicely and exit with an error
            result = axapi_call_v3(module, axapi_base_url + 'logoff', method="POST", signature=signature, body="")
            module.fail_json(msg=result['response']['err']['msg'])
        else:
            changed = True        

    # log out of the session nicely and exit
    result = axapi_call_v3(module, axapi_base_url + 'logoff', method="POST", signature=signature, body="")
    module.exit_json(changed=changed, content=result)

# standard ansible module imports
from ansible.module_utils.basic import *
from ansible.module_utils.urls import *
from ansible.module_utils.a10 import *
import mimetools
import mimetypes
import io

if __name__ == '__main__':
    main()
