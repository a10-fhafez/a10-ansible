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
module: a10_health_monitor
version_added: 1.8
short_description: Manage A10 Networks AX/SoftAX/Thunder/vThunder devices
description:
    - Manage slb health monitor objects on A10 Networks devices via aXAPI
author: "Fadi Hafez (@fhafez)"
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
      - L3V partition to add these health monitors to
    required: false
    default: null
    choices: []
  hm_name:
    description:
      - health monitor name
    required: true
    aliases: ['hm']
  interval:
    description:
      - hm interval in seconds
    required: false
    default: 5
    aliases: ['int']
  timeout:
    description:
      - hm timeout in seconds
    required: false
    default: 5
  retry:
    description:
      - hm retry count
    required: false
    default: 3
  consec_pass_reqd:
    description:
      - consecutive passes required
    required: false
    default: 1
  disable_after_down:
    description:
      - keep disabled when down
    required: false
    default: false
    choices: ['0', '1']
  icmp:
    description:
      - make a icmp health monitor
    required: false
    default: []
  tcp:
    description:
      - make a tcp health monitor
    required: false
    default: []
  udp:
    description:
      - make a udp health monitor
    required: false
    default: []
  http:
    description:
      - make a http health monitor
    required: false
    default: []
  https:
    description:
      - make a https health monitor
    required: false
    default: []
  ftp:
    description:
      - make an ftp health monitor
    required: false
    default: []
  smtp:
    description:
      - make an smtp health monitor
    required: false
    default: []
  pop3:
    description:
      - make an pop3 health monitor
    required: false
    default: []
  snmp:
    description:
      - make an snmp health monitor
    required: false
    default: []
  dns:
    description:
      - make an dns health monitor
    required: false
    default: []
  radius:
    description:
      - make an radius health monitor
    required: false
    default: []
  ldap:
    description:
      - make an ldap health monitor
    required: false
    default: []
  rtsp:
    description:
      - make an rtsp health monitor
    required: false
    default: []
  sip:
    description:
      - make an sip health monitor
    required: false
    default: []
  ntp:
    description:
      - make an ntp health monitor
    required: false
    default: []
  imap:
    description:
      - make an imap health monitor
    required: false
    default: []
  database:
    description:
      - make an database health monitor
    required: false
    default: []
  compound:
    description:
      - make an compound health monitor
    required: false
    default: []
  database:
    description:
      - make an database health monitor
    required: false
    default: []
  external:
    description:
      - make an external health monitor
    required: false
    default: []
  state:
    description:
      - absent or present for delete or creating of HM
    required: false
    default: absent 
    choices: ["present", "absent"]
  write_config:
    description:
      - If C(yes), any changes will cause a write of the running configuration
        to non-volatile memory. This will save I(all) configuration changes,
        including those that may have been made manually or through other modules,
        so care should be taken when specifying C(yes).
    required: false
    version_added: 2.2
    default: "no"
    choices: ["yes", "no"]
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
# Create a new health monitor
- a10_health_monitor_v2: 
    host: a10.mydomain.com
    username: myadmin
    password: mypassword
    partition: RCSIN_PRV
    hm_name: ws_hm
    interval: 4
    timeout: 4
    retry: 2
    disable_after_down: true
    consec_pass_reqd: 1
    external:
      - program: checkServerStatus
        server_port: 2245
        arguments: ""
        preference: 1
'''

def main():
    argument_spec = a10_argument_spec()
    argument_spec.update(url_argument_spec())
    argument_spec.update(
        dict(
            state=dict(type='str', default='present', choices=['present', 'absent']),
            partition=dict(type='str', aliases=['partition','part'], required=False),
            hm_name=dict(type='str', aliases=['hm'], required=True),
            interval=dict(type='str', default='5', aliases=['int']),
            timeout=dict(type='str', default='5'),
            retry=dict(type='str', default='3'),
            disable_after_down=dict(type='str', default='1', choices=['0','1']),
            consec_pass_reqd=dict(type='str', default='1'),
            icmp=dict(type='list', default=[]),
            tcp=dict(type='dict', default={}),
            udp=dict(type='dict', default={}),
            http=dict(type='dict', default={}),
            https=dict(type='dict', default={}),
            ftp=dict(type='dict', default={}),
            smtp=dict(type='dict', default={}),
            pop3=dict(type='dict', default={}),
            snmp=dict(type='dict', default={}),
            dns=dict(type='dict', default={}),
            radius=dict(type='dict', default={}),
            ldap=dict(type='dict', default={}),
            rtsp=dict(type='dict', default={}),
            sip=dict(type='dict', default={}),
            ntp=dict(type='dict', default={}),
            imap=dict(type='dict', default={}),
            database=dict(type='dict', default={}),
            compound=dict(type='dict', default={}),
            external=dict(type='dict', default={})
        )
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=False
    )

    # retrieve all the parameters
    state = module.params['state']
    host = module.params['host']
    username = module.params['username']
    password = module.params['password']
    part = module.params['partition']
    write_config = module.params['write_config']
    hm_name = module.params['hm_name']
    interval = module.params['interval']
    timeout = module.params['timeout']
    retry = module.params['retry']
    disable_after_down = module.params['disable_after_down']
    consec_pass_reqd = module.params['consec_pass_reqd']
    icmp = module.params['icmp']
    tcp = module.params['tcp']
    udp = module.params['udp']
    http = module.params['http']
    https = module.params['https']
    ftp = module.params['ftp']
    smtp = module.params['smtp']
    pop3 = module.params['pop3']
    snmp = module.params['snmp']
    dns = module.params['dns']
    radius = module.params['radius']
    ldap = module.params['ldap']
    rtsp = module.params['rtsp']
    sip = module.params['sip']
    ntp = module.params['ntp']
    imap = module.params['imap']
    database = module.params['database']
    compound = module.params['compound']
    external = module.params['external']
    state = module.params['state']

    # the only required parameter is hm_name
    if hm_name is None:
        module.fail_json(msg='hm_name is required')

    axapi_base_url = 'https://%s/services/rest/V2.1/?format=json' % host
    session_url = axapi_authenticate(module, axapi_base_url, username, password)

    # change partitions if we need to
    if part:
        result = axapi_call(module, session_url + '&method=system.partition.active', json.dumps({'name': part}))
        if (result['response']['status'] == 'fail'):
            module.fail_json(msg=result['response']['err']['msg'])

    # absent means to delete the health monitor (only the hm_name is required)
    if state == 'absent':
        json_post = {
            'health_monitor': {
                'name': hm_name,
            }
        }

    else:

        # build the json_post
        json_post = {
            'health_monitor': {
                'name': hm_name,
                'interval': interval,
                'timeout': timeout,
                'retry': retry,
                'disable_after_down': disable_after_down,
                'consec_pass_reqd': consec_pass_reqd,
            }
        }
 
        # add the right type to the json_post (there are 0 to 18 types)
        if icmp:
            json_post['health_monitor']['type'] = 0
            json_post['health_monitor']['icmp'] = icmp

        elif tcp:
            json_post['health_monitor']['type'] = 1
            json_post['health_monitor']['tcp'] = tcp

        elif udp:
            json_post['health_monitor']['type'] = 2
            json_post['health_monitor']['udp'] = udp
       
        elif http:
            json_post['health_monitor']['type'] = 3
            json_post['health_monitor']['http'] = http
       
        elif https:
            json_post['health_monitor']['type'] = 4
            json_post['health_monitor']['https'] = https
       
        elif ftp:
            json_post['health_monitor']['type'] = 5
            json_post['health_monitor']['ftp'] = ftp
       
        elif smtp:
            json_post['health_monitor']['type'] = 6
            json_post['health_monitor']['smtp'] = smtp
       
        elif pop3:
            json_post['health_monitor']['type'] = 7
            json_post['health_monitor']['pop3'] = pop3
       
        elif snmp:
            json_post['health_monitor']['type'] = 8
            json_post['health_monitor']['snmp'] = snmp
       
        elif dns:
            json_post['health_monitor']['type'] = 9
            json_post['health_monitor']['dns'] = dns
       
        elif radius:
            json_post['health_monitor']['type'] = 10
            json_post['health_monitor']['radius'] = radius
       
        elif ldap:
            json_post['health_monitor']['type'] = 11
            json_post['health_monitor']['ldap'] = ldap
       
        elif rtsp:
            json_post['health_monitor']['type'] = 12
            json_post['health_monitor']['rtsp'] = rtsp
       
        elif sip:
            json_post['health_monitor']['type'] = 13
            json_post['health_monitor']['sip'] = sip
       
        elif ntp:
            json_post['health_monitor']['type'] = 14
            json_post['health_monitor']['ntp'] = ntp
       
        elif imap:
            json_post['health_monitor']['type'] = 15
            json_post['health_monitor']['imap'] = imap
       
        elif database:
            json_post['health_monitor']['type'] = 16
            json_post['health_monitor']['database'] = database
       
        elif compound:
            json_post['health_monitor']['type'] = 17
            json_post['health_monitor']['compound'] = compound
       
        elif external:
            json_post['health_monitor']['type'] = 18
            json_post['health_monitor']['external'] = external
       
        else:
            module.fail_json(msg="you must specify either icmp, tcp, udp, http, https, ftp, smtp, pop3 etc.")


    changed = False

    # present means the health monitor is being added
    if state == 'present':
        if not hm_name:
            module.fail_json(msg='you must specify a name when creating a health monitor')

        result = axapi_call(module, session_url + '&method=slb.hm.create', json.dumps(json_post))
        if axapi_failure(result):
            module.fail_json(msg="failed to create the health monitor: %s" % result['response']['err']['msg'])

        changed = True

    elif state == 'absent':
        result = axapi_call(module, session_url + '&method=slb.hm.delete', json.dumps(json_post['health_monitor']))
        if axapi_failure(result):
            module.fail_json(msg="failed to delete the health monitor: %s" % result['response']['err']['msg'])

        changed = True


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

main()
