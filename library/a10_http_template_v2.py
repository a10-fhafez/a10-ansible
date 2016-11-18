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
module: a10_http_template
version_added: 2.2.0.0
short_description: Manage A10 Networks AX/SoftAX/Thunder/vThunder devices
description:
    - Manage http template objects on A10 Networks devices via aXAPI
author: Fadi Hafez using works of Mischa Peters
notes:
    - Requires A10 Networks aXAPI 2.1
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
      - L3V partition to add the ACL to.  Will be added to 'shared' if not specified
    required: false
    default: null
    choices: []
  state:
    description:
      - create, update or remove acl
    required: false
    default: present
    choices: ['present', 'absent']
  name:
    description:
      - name of the template
    required: true
  url_switching_list:
    description:
      - a list of url switching parameters, to switch traffic to a different service group if url startswith/contains/endswith a specified string
      - each list item must contain url, service_group, match_method
      - match_method can be 0=contains, 1=startswith, 2=endswith, 3=equals
    required: false
    default: null
  host_switching_list:
    description:
      - a list of host switching parameters, to switch traffic to a different service group if host startswith/contains/endswith a specified string
      - each list item must contain host, service_group, match_method
      - match_method can be 0=contains, 1=startswith, 2=endswith
    required: false
    default: null
  write_config:
    description:
      - If C(yes), any changes will cause a write of the running configuration
        to non-volatile memory. This will save I(all) configuration changes,
        including those that may have been made manually or through other modules,
        so care should be taken when specifying C(yes).
    required: false
    version_added: 2.2
    default: 'no'
    choices: ['yes', 'no']
  validate_certs:
    description:
      - If C(no), SSL certificates will not be validated. This should only be used
        on personally controlled devices using self-signed certificates.
    required: false
    version_added: 2.2.0.0
    default: 'yes'
    choices: ['yes', 'no']

'''

EXAMPLES = '''
# Create a new HTTP Template
- a10_http_template: 
    host: a10.mydomain.com
    username: myadmin
    password: mypassword
    name: my_http_templ
    url_switching_list:
      - url: english
        service_group: sg-80-tcp
        match_method: 0
'''


def main():
    argument_spec = a10_argument_spec()
    argument_spec.update(url_argument_spec())
    argument_spec.update(
        dict(
            state=dict(type='str', default='present', choices=['present', 'absent']),
            partition=dict(type='str', aliases=['partition','part'], required=False),
            name=dict(type='str', required=True),
            url_switching_list=dict(type='list', default=[]),
            host_switching_list=dict(type='list', default=[]),
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
    write_config = module.params['write_config']
    name = module.params['name']

    url_switching_list = module.params['url_switching_list']
    host_switching_list = module.params['host_switching_list']

    if name is None:
        module.fail_json(msg='name is required')

    axapi_base_url = 'https://%s/services/rest/V2.1/?format=json' % host
    session_url = axapi_authenticate(module, axapi_base_url, username, password)

    # change partitions if we need to
    if part:
        result = axapi_call(module, session_url + '&method=system.partition.active', json.dumps({'name': part}))
        if (result['response']['status'] == 'fail'):
            module.fail_json(msg=result['response']['err']['msg'])

        # need to prepend the service_group with the partition name in url and host switching templates
        if url_switching_list:
            for item in url_switching_list:
                item['service_group'] = '?' + part + '?' + item['service_group']

        if host_switching_list:
            for item in url_switching_list:
                item['service_group'] = '?' + part + '?' + item['service_group']


    # populate the json body for the creation of the http template
    json_post = {
        'http_template': {
            'name': name,
        }
    }

    if url_switching_list:
        json_post['url_switching_list'] = url_switching_list

    if host_switching_list:
        json_post['host_switching_list'] = host_switching_list

   
    # check to see if this http_template exists
    http_template_data = axapi_call(module, session_url + '&method=slb.template.http.search', json.dumps({'name': name}))
    http_template_exists = not axapi_failure(http_template_data)

    changed = False
    if state == 'present':
        result = axapi_call(module, session_url + '&method=slb.template.http.create', json.dumps(json_post))
        if axapi_failure(result):
            module.fail_json(msg="failed to create the http template: %s" % result['response']['err']['msg'])

        changed = True

    elif state == 'absent':
        if http_template_exists:
            result = axapi_call(module, session_url + '&method=slb.template.http.delete', json.dumps({'name': name}))
            changed = True
        else:
            result = dict(msg="the http template was not present")

    # if the config has changed, save the config unless otherwise requested
    if changed and write_config:
        write_result = axapi_call(module, session_url + '&method=system.action.write_memory')
        if axapi_failure(write_result):
            module.fail_json(msg="failed to save the configuration: %s" % write_result['response']['err']['msg'])

    # log out of the session nicely and exit
    axapi_call(module, session_url + '&method=session.close')
    module.exit_json(changed=changed, content=result)

# standard ansible module imports
from ansible.module_utils.basic import *
from ansible.module_utils.urls import *
from ansible.module_utils.a10 import *

if __name__ == '__main__':
    main()
