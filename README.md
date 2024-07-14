# ansible-modules

This repo contains a few ansible modules that I have written that could be of possible
use to others either in their infrastructure or as an example to be adapted.

## iptables\_chain module

I wrote the iptables\_chain module as it was very slow and laborious to write a bunch
of tasks that would each add a single rule, while on the other hand using iptables-restore
to load up a single template of rules would not play nice with certain services that
need to update the rules themselves, such as kubernetes and fail2ban. As iptables is now
generally deprecated in favor of nftables, this module is likely of little use as-is, but
it could be easily adapted to a similar nftables\_chain module.

The solution to this problem was to be able to insert an entire chain at a specified position
in the INPUT, OUTPUT, or other chain that would encode all security and other rules needed
by an organization while allowing other applications to insert their own chains or edit
chains as needed. I wanted to be able to load a single chain at a specified position with a
single Ansible task, so I wrote a module to take a file specifying a chain in the format
used by iptables-restore
existing on the host machine, and insert it at the specified position in a specified
chain.

For example, on a host allowing incoming connections from an internal network generally,
and http/https connections from the outside world, but blocking all other incoming
connections from outside, the following example rules might be desirable inserted at the
end of the INPUT chain, where on some host we might expect an application such as
fail2ban to also insert reject rules at the beginning of INPUT:

```
*filter
-F EXAMPLE-INPUT

# Allow loopback, icmp, related, and established connections
-A EXAMPLE-INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
-A EXAMPLE-INPUT -p icmp --icmp-type 13 -j DROP
-A EXAMPLE-INPUT -p icmp --icmp-type 14 -j DROP
-A EXAMPLE-INPUT -p icmp -j ACCEPT
-A EXAMPLE-INPUT -i lo -j ACCEPT

# Allow all traffic from the internal network
-A EXAMPLE-INPUT -s 192.168.0.0/16 -j ACCEPT

# Allow incoming http/https connections from everywhere
-A EXAMPLE-INPUT -p tcp -m state --state NEW -m tcp --dport 80 -j ACCEPT
-A EXAMPLE-INPUT -p tcp -m state --state NEW -m tcp --dport 443 -j ACCEPT

# Otherwise reject incoming connections
-A EXAMPLE-INPUT -p udp -j REJECT --reject-with icmp-port-unreachable
-A EXAMPLE-INPUT -p tcp -j REJECT --reject-with tcp-reset
-A EXAMPLE-INPUT -j REJECT --reject-with icmp-proto-unreachable

-A EXAMPLE-INPUT -j RETURN
COMMIT
```

With this module installed in the controller library, the following task will
install these rules at the beginning of the INPUT chain:

```
- name: Ensure the EXAMPLE-INPUT chain is inserted at the end of the INPUT chain
  iptables_chain:
    spec: /path/to/above/example/on/host/example-input.chain
    name: EXAMPLE-INPUT
    parent: INPUT
    table: filter
    position: end
    ip_version: ipv4
```

Note that the specification file will need to be previously rendered by a copy, template,
or other task which places it in /path/to/above/example/on/host/example-input.chain

Other example usage can be found in the module code itself.

When the module inserts the chain, it also adds a special comment rule with md5sums
for the inserted chain so that on subsequent playbook runs it can detect that no change is
required and return ok with an unchanged state for the task.

