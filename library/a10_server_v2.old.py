#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
Ansible module to manage A10 Networks slb server objects
(c) 2014, Mischa Peters <mpeters@a10networks.com>
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
module: a10_server
version_added: 1.0
short_description: Manage A10 Networks AX/SoftAX/Thunder/vThunder devices
description:
    - Manage slb server objects on A10 Networks devices via aXAPI
author: Mischa Peters
notes:
    - Requires A10 Networks aXAPI 2.1
requirements:
    - urllib2
    - re
options:
  host:
    description:
      - hostname or ip of your A10 Networks device
    required: true
    default: null
    aliases: []
    choices: []
  username:
    description:
      - admin account of your A10 Networks device
    required: true
    default: null
    aliases: ['user', 'admin']
    choices: []
  password:
    description:
      - admin password of your A10 Networks device
    required: true
    default: null
    aliases: ['pass', 'pwd']
    choices: []
  partition:
    description:
      - L3V partition to add these servers to
    required: false
    default: null
    choices: []
  server_name:
    description:
      - slb server name
    required: true
    default: null
    aliases: ['server']
    choices: []
  server_ip:
    description:
      - slb server IP address
    required: false
    default: null
    aliases: ['ip', 'address']
    choices: []
  server_port:
    description:
      - slb server port
    required: false
    default: null
    aliases: ['port']
    choices: []
  server_protocol:
    description:
      - slb server protocol
    required: false
    default: null
    aliases: ['proto', 'protocol']
    choices: ['tcp', 'udp']
  server_status:
    description:
      - slb server status
    required: false
    default: enabled
    aliases: ['status']
    choices: ['enable', 'disable']
  state:
    description:
      - create, update or remove slb server
    required: false
    default: present
    aliases: []
    choices: ['present', 'absent']
'''

EXAMPLES = '''
# Create a new server
ansible host -m a10_server -a "host=a10adc.example.com username=axapiuser password=axapipass server_name=realserver1 server_ip=192.168.1.23"
# Add a port
ansible host -m a10_server -a "host=a10adc.example.com username=axapiuser password=axapipass server_name=realserver1 server_port=80 server_protocol=tcp"
# Disable a server
ansible host -m a10_server -a "host=a10adc.example.com username=axapiuser password=axapipass server_name=realserver1 server_status=disable"
'''

import urllib2


def axapi_call(url, post=None):
    result = urllib2.urlopen(url, post).read()
    return result


def axapi_authenticate(base_url, user, pwd):
    url = base_url + '&method=authenticate&username=' + user + \
        '&password=' + pwd
    result = json.loads(axapi_call(url))
    if 'response' in result:
        return module.fail_json(msg=result['response']['err']['msg'])
    sessid = result['session_id']
    return base_url + '&session_id=' + sessid


def main():
    global module
    module = AnsibleModule(
        argument_spec=dict(
            host=dict(type='str', required=True),
            username=dict(type='str', aliases=['user', 'admin'],
                          required=True),
            password=dict(type='str', aliases=['pass', 'pwd'], required=True),
            partition=dict(type='str', aliases=['partition','part'], required=False),
            server_name=dict(type='str', aliases=['server'], required=True),
            server_ip=dict(type='str', aliases=['ip', 'address']),
            server_port=dict(type='int', aliases=['port']),
            server_protocol=dict(type='str', aliases=['proto', 'protocol'],
                                 choices=['tcp', 'udp']),
            server_status=dict(type='str', default='enable',
                               aliases=['status'],
                               choices=['enable', 'disable']),
            state=dict(type='str', default='present',
                       choices=['present', 'absent']),
        ),
        supports_check_mode=False
    )

    host = module.params['host']
    user = module.params['username']
    pwd = module.params['password']
    part = module.params['partition']
    slb_server = module.params['server_name']
    slb_server_ip = module.params['server_ip']
    slb_server_port = module.params['server_port']
    slb_server_proto = module.params['server_protocol']
    slb_server_status = module.params['server_status']
    state = module.params['state']

    axapi_base_url = 'http://' + host + '/services/rest/V2.1/?format=json'

    if slb_server_proto == 'tcp' or slb_server_proto == 'TCP' or \
            slb_server_proto is None:
        protocol = '2'
    else:
        protocol = '3'

    if slb_server_status == 'enable':
        status = '1'
    else:
        status = '0'

    if slb_server is None:
        module.fail_json(msg='server_name is required')

    if slb_server_port is None:
        json_post = {'server': {'name': slb_server,
                                'host': slb_server_ip, 'status': status}}
    else:
        json_post = {'server': {'name': slb_server, 'host': slb_server_ip,
                                'status': status, 'port_list':
                                [{'port_num': slb_server_port,
                                  'protocol': protocol}]}}

    try:
        session_url = axapi_authenticate(axapi_base_url, user, pwd)

        if part:
            response = axapi_call(session_url + '&method=system.partition.active',
                                            json.dumps({'name': part}))
            result = json.loads(response)
            if (result['response']['status'] == 'fail'):
                module.fail_json(msg=result['response']['err']['msg'])

        if state == 'present':
            response = axapi_call(session_url + '&method=slb.server.search',
                                  json.dumps({'name': slb_server}))
            slb_server_exist = re.search(slb_server, response, re.I)

            if slb_server_exist is None:
                if slb_server_ip is None:
                    module.fail_json(msg='IP address is required')
                response = axapi_call(session_url +
                                      '&method=slb.server.create',
                                      json.dumps(json_post))
            else:
                response = axapi_call(session_url +
                                      '&method=slb.server.update',
                                      json.dumps(json_post))

        if state == 'absent':
            response = axapi_call(session_url +
                                  '&method=slb.server.delete',
                                  json.dumps({'name': slb_server}))

        result = json.loads(response)
        axapi_call(session_url + '&method=session.close')

    except Exception, e:
        return module.fail_json(msg='received exception: %s' % e)

    if 'respone' in result and 'err' in result['response']:
        return module.fail_json(msg=result['response']['err']['msg'])

    module.exit_json(changed=True, content=result)

from ansible.module_utils.basic import *
main()
