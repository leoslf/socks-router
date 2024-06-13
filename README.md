# socks-router

Thin facade layer on top of openssh's dynamic proxy with slightly more sophiscated configurable routing rules

## Usage

```bash
socks-router --help
```

## Routing Table

### Grammar

```text
routing_table := "" | comment | routing_rule [[comment] end_of_line routing_table]
routing_rule := upstream_address whitespaces patterns
comment := [whitespaces] "#"  [whitespaces] .*

upstream_address := [upstream_scheme "://"] address
address := ipv4_address | ipv6_address | host_address

upstream_scheme := "ssh" | "socks5" | "socks5h"

patterns := pattern [whitespaces patterns]
pattern := ["!"] "[^ \t\r\n]+"

ipv4_address := ipv4 [":" port]
ipv6_address := ("[" ipv6 "]:" port) | ipv6
host_address := host [":" port]

whitespaces := whitespace | whitespaces
whitespace := " " | "\t"
end_of_line := "\r\n" | "\r" | "\n"
```


### Example

```text
# ~/.ssh/routes

# default upstream scheme: ssh://
# use ssh host foo's dynamic proxy to connect to bar.com
foo bar.com
# use ssh host foo's dynamic proxy to connect to *.bar.com
foo *.bar.com
# use ssh host foo's dynamic proxy to connect to *.google.com but abc.bar.com
foo *.bar.com !abc.bar.com
ssh://foo *.google.com

# transparent socks5 / socks5h upstreams
# perform DNS resolution in socks-router
socks5://foo-bar.baz hello-world.com
# defer the DNS resolution to upstream
socks5h://foo-bar.baz hello-world.com
```

## Development

```bash
poetry install

poetry run pytest --cov-report html
```

NOTE: pre-commit hooks are set up
