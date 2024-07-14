# -*- coding: utf-8 -*-

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: iptables_chain
short_description: Loads in rules for an iptables chain from a specification file
version_added: "2.14"
author:
- Eric Appelt (@appeltel) <eric.appelt@gmail.com>
description:
  - This module looks for a "spec file" on the host which contains the rules
    for an iptables chain in a format suitable for use with "iptables-restore"
    with restrictions
  - The spec file must indicate the table this chain is applied to in the first
    line, it must have a command to flush the named chain in the second line,
    and further lines must be append actions applied to the named chain.
    The final line must be a COMMIT statement.
    Empty lines and lines containing only comments are allowed, but if there
    is any other deviation this module will intentionally fail.
  - The rules for the chain are loaded as indicated in the spec file without
    flushing any other chains
  - A command to jump to the named chain is inserted or appended to the specified
    parent chain at an indicated numeric position, or "begin" indicating the
    first rule of the chain, or "end" indicating an append to the end of the parent
    chain
  - Any other commands calling the named chain from the parent chain in other
    positions are removed
  - A special comment rule is added to the named chain with md5sums of the spec
    file and the chain itself so that if this play is re-run without changes
    to the spec file or loaded chain it will not need to make any updates. 
'''

EXAMPLES = r'''
- name: Load the EXAMPLE_TEST chain rules and append to end of INPUT
  iptables_chain:
    spec: /etc/sysconfig/iptables.chain.EXAMPLE_TEST
    name: EXAMPLE_TEST
    parent: INPUT
    table: filter
    ip_version: ipv4
    position: end

- name: Load the EXAMPLE_TEST2 chain rules at the beginning of OUTPUT
  iptables_chain:
    spec: /etc/sysconfig/iptables.chain.EXAMPLE_TEST2
    name: EXAMPLE_TEST2
    parent: OUTPUT
    table: filter
    position: begin

- name: Load the EXAMPLE_TEST3 chain rules at position 3 of INPUT
  iptables_chain:
    spec: /etc/sysconfig/iptables.chain.EXAMPLE_TEST3
    name: EXAMPLE_TEST3
    parent: INPUT
    table: filter
    position: 3
'''

RETURN = r'''
spec:
    description: Absolute path to the "spec file" on the host with the chain rules
    type: str
    returned: always
    sample: /etc/sysconfig/iptables.chain.EXAMPLE_TEST1
name:
    description: Name of the chain to be configured and inserted/appended
    type: str
    returned: always
    sample: EXAMPLE_TEST1
parent:
    description: Name of the parent chain that the named chain will be inserted into
    type: str
    returned: always
    sample: INPUT
table:
    description: Name of the table that the chain should be added to (i.e. nat, filter, etc)
    type: str
    returned: always
    sample: filter
position:
    description: Numeric position or "begin" or "end" of the parent chain where the named chain will be called
    type: str
    returned: always
    sample: end
ip_version:
    description: IP protocol version, either "ipv4" or "ipv6"
    type: str
    returned: always
    sample: ipv4
'''

import hashlib
import os
import sys

from ansible.module_utils.basic import AnsibleModule


PYTHON2_INTERPRETER = sys.version_info[0] < 3

BINS = dict(
    ipv4='iptables',
    ipv6='ip6tables',
)

def md5sum(text):
    if PYTHON2_INTERPRETER:
        return hashlib.md5(text).hexdigest()
    else:
        return hashlib.md5(text.encode('utf-8')).hexdigest()


class IPTablesChain(object):
    """
    Manages iptables chain from a rule specification file
    """
    def __init__(self):
        self.module = AnsibleModule(
            supports_check_mode=False,
            argument_spec={
                'spec': {'type': 'str'},
                'name': {'type': 'str'},
                'parent': {'type': 'str'},
                'table': {'type': 'str', 'default': 'filter'},
                'position': {'type': 'str'},
                'ip_version': {'type': 'str', 'default': 'ipv4'}
            }
        )
        self.args = {
            'changed': False,
            'failed': False,
            'spec': self.module.params['spec'],
            'name': self.module.params['name'],
            'parent': self.module.params['parent'],
            'table': self.module.params['table'],
            'position': self.module.params['position'],
            'ip_version': self.module.params['ip_version']
        }

        if self.args['ip_version'] not in ['ipv4', 'ipv6']:
            self.module.fail_json(msg="ip_version must be ipv4 or ipv6")

        if self.args['position'] not in ['begin', 'end']:
            try:
                int(self.args['position'])
            except ValueError:
                self.module.fail_json(msg="position must be begin, end, or an integer")

        if self.args['position'] == 'begin':
            self.args['position'] = '1'

        if not os.path.isfile(self.args['spec']):
            self.module.fail_json(msg="Specification file does not exist")
    
        self.rulespec = open(self.args['spec']).read()
        self.validate_spec()

        self.iptables_path = self.module.get_bin_path(BINS[self.args['ip_version']], True)
        self.iptables_restore_path = self.module.get_bin_path(
            BINS[self.args['ip_version']] + '-restore',
            True
        )

    def main(self):
        """
        Perform updates to the iptables chains if needed and
        exit module
        """
        chain_exists, current_rules = self.get_current_rules()
    
        if not chain_exists:
            self.create_chain()
            self.args['changed'] = True

        if self.update_required(current_rules):
            self.reload_rules()
            self.append_comment_hash_rule()
            self.args['changed'] = True

        parent_length, positions = self.get_current_positions()

        # Append chain at end if end selected as position if needed
        # otherwise insert at specified position if needed
        if self.args['position'] == 'end':
            # note iptables rules are indexed starting at 1
            if parent_length not in positions:
                self.append_chain_target()
                self.args['changed'] = True
        else:
            target_pos = int(self.args['position'])
            if target_pos not in positions:
                self.insert_chain_target(target_pos)
                self.args['changed'] = True

        # if there was only one rule targeting the named chain
        # and no changes were made we can exit now
        if len(positions) == 1 and self.args['changed'] == False:
             self.module.exit_json(**self.args)

        # Check for additonal misplaced rules targeting named
        # chain and delete them starting from the greatest rule
        parent_length, positions = self.get_current_positions()
        while(positions):
            pos = positions.pop()
            if self.args['position'] == 'end' and pos == parent_length:
                continue
            elif self.args['position'] == str(pos):
                continue
            self.delete_chain_target(pos)
            self.args['changed'] = True

        self.module.exit_json(**self.args)

    def validate_spec(self):
        """
        Exits with an error if the rule specification file is invalid
        """
        rulespec_raw = self.rulespec.splitlines()
        rulespec = []
    
        # remove comments and empty lines
        for line in rulespec_raw:
            if not line.strip():
                continue
            if line.strip().startswith('#'):
                continue
            rulespec.append(line.strip())
    
        if len(rulespec) < 3:
            self.module.fail_json(msg="Specification file must contain at minimum a table name, flush command, and commit")
        
    
        # Spec must end with COMMIT
        if rulespec.pop() != 'COMMIT':
            self.module.fail_json(msg="Specification file must end with COMMIT")
    
        # Spec must mark the correct table
        if rulespec.pop(0) != '*{}'.format(self.args['table']):
            self.module.fail_json(msg="Specification file must begin marking the table specified in the play")
    
        # Spec must begin with a flush command
        flush_cmd = rulespec.pop(0)
        fields = flush_cmd.split()
        if (
            (len(fields) < 2) or
            (fields[0] not in ['-F', '--flush']) or
            (fields[1] != self.args['name'])
        ):
            self.module.fail_json(msg="First command of the specification file must flush the chain designated in the play")
    
        for line in rulespec:
            fields = line.split()
            if (len(fields) < 2) or (fields[0] not in ['-A', '--append']): 
                self.module.fail_json(msg="Only append commands allowed after initial flush")
            if fields[1] != self.args['name']:
                self.module.fail_json(msg="Specification file commands must apply to the specified chain in the play")

    def get_current_positions(self):
        """
        Get the current positions of the named chain as targets in the specified parent
        chain. Return a tuple containing first the length of the parent chain and second
        a list of integers indicating the positions of the named chain as targets.
        """
        cmd = [
            self.iptables_path,
            '-t', self.args['table'],
            '-L', self.args['parent'],
            '--line-numbers'
        ]
        rc, rules_raw, _ = self.module.run_command(cmd, check_rc=False)
        positions = []
        length = 0
        for line in rules_raw.splitlines():
            fields = line.split()
            try:
                pos = int(fields[0])
            except Exception:
                continue
            length += 1
            if fields[1] == self.args['name']:
                positions.append(pos)
        return length, positions

    def get_current_rules(self):
        """
        Get the current rules for the chain if it exists. Return a tuple where
        the first value is true/false if the chain exists, and the second is a
        string representing all the rules
        """
        cmd = [self.iptables_path, '-t', self.args['table'], '-S', self.args['name']]
        rc, rules, _ = self.module.run_command(cmd, check_rc=False)
        if rc != 0:
            return False, ""
        else:
            return True, rules

    def append_chain_target(self):
        cmd = [
            self.iptables_path,
            '-t', self.args['table'],
            '-A', self.args['parent'],
            '-j', self.args['name']
        ]
        _, _, _ = self.module.run_command(cmd, check_rc=True)

    def insert_chain_target(self, pos):
        cmd = [
            self.iptables_path,
            '-t', self.args['table'],
            '-I', self.args['parent'], str(pos),
            '-j', self.args['name']
        ]
        _, _, _ = self.module.run_command(cmd, check_rc=True)

    def delete_chain_target(self, pos):
        cmd = [
            self.iptables_path,
            '-t', self.args['table'],
            '-D', self.args['parent'], str(pos)
        ]
        _, _, _ = self.module.run_command(cmd, check_rc=True)

    def update_required(self, rules):
        """
        This checks if the rules need to be reloaded, which could be due to a change
        in the rule specification file or due to a change in the rules that are have
        been loaded into the chain.

        This module is able to track these by appending a comment onto the chain after
        loading all the rules in the rulespec file. This comment has the md5sums of
        both the specification file and the loaded rules (which may be formatted
        differently). By comparing the md5sums in this comment with the current
        rulespec file and the current loaded rules (omitting the comment rule) it
        is possible to determine if the rules need to be reloaded from the spec file.
        """
        found_comment = False
        md5_cur_spec = ""
        md5_cur_rules = ""
        for line in rules.splitlines():
            if not '__ansible_chain' in line or not '--comment' in line:
                continue
            found_comment = True
            fields = line.split()
            for idx, val in enumerate(fields):
                if val == "spec":
                    md5_cur_spec = fields[idx + 1]
                if val == "rules":
                    md5_cur_rules = fields[idx + 1]
            break

        if not found_comment:
            return True
        lines = rules.splitlines()
        nocomment = []
        for line in lines:
            if '__ansible_chain' in line and '--comment' in line:
                continue
            nocomment.append(line)
        rules = '\n'.join(nocomment) + '\n'

        md5_rules = md5sum(rules)
        md5_spec = md5sum(self.rulespec)
        if md5_rules == md5_cur_rules and md5_spec == md5_cur_spec:
            return False
        return True

    def reload_rules(self):
        cmd = [self.iptables_restore_path, '-n', self.args['spec']]
        rc, _, _ = self.module.run_command(cmd, check_rc=True)
        return rc

    def append_comment_hash_rule(self):
        _, rules = self.get_current_rules()
        md5_rules = md5sum(rules)
        md5_spec = md5sum(self.rulespec)
        comment = "__ansible_chain spec {} rules {} ".format(md5_spec, md5_rules)
        cmd = [
            self.iptables_path,
            '-t', self.args['table'],
            '-A', self.args['name'],
            '-m', 'comment', '--comment', comment
        ]
        rc, _, _ = self.module.run_command(cmd, check_rc=True)
        return rc

    def create_chain(self):
        cmd = [self.iptables_path, '-t', self.args['table'], '-N', self.args['name']]
        rc, _, _ = self.module.run_command(cmd, check_rc=True)
        return rc



if __name__ == '__main__':
    iptc = IPTablesChain()
    iptc.main()
