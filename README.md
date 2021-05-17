# mctop is an Archived Project

mctop is no longer actively maintained. Your mileage with patches may vary.

# mctop

Inspired by "top", mctop passively sniffs the network traffic passing in and out of a
server's network interface and tracks the keys responding to memcache get commands. The output
is presented on the terminal and allows sorting by total calls, requests/sec and
bandwidth.

You can read more detail about why this tool evovled over on our
[code as craft](http://codeascraft.etsy.com/2012/12/13/mctop-a-tool-for-analyzing-memcache-get-traffic) blog.

mctop depends on the [ruby-pcap](https://rubygems.org/gems/ruby-pcap) gem, if you don't have
this installed you'll need to ensure you have the development pcap libraries (libpcap-devel
package on most linux distros) to build the native gem.

![](http://etsycodeascraft.files.wordpress.com/2012/12/mctop.jpg)

## How it works

mctop sniffs network traffic collecting memcache `VALUE` responses and calculates from
traffic statistics for each key seen.  It currently reports on the following metrics per key:

* **calls** - the number of times the key has been called since mctop started
* **objsize** - the size of the object stored for that key
* **req/sec** - the number of requests per second for the key
* **%reqs** - this key's percentage of total requests
* **bw (KB/s)** - the estimated network bandwidth consumed by this key in kilobytes per second
* **%bw** - this key's percentage of total bandwidth

## Getting it running

the quickest way to get it running is to:

* ensure you have libpcap-devel installed
* git clone this repo
* in the top level directory of this repo `bundle install` (this will install the deps)
* then either:
    * install it locally `rake install`; or
    * run it from the repo (good for hacking) `sudo ./bin/mctop --help`

Note: the ruby-pcap gem version 0.7.9 does not work older versions of ruby (at
least 2.0.0); on old systems, install ruby-pcap 0.7.8.

## Command line options

    Usage: mctop [options]
        -a, --agg-filter=REGEX           Regex to filter keys; aggregates on first capture group
        -i, --interface=NIC              Network interface to sniff (required)
        -p, --port=PORT                  Network port to sniff on (default 11211)
            --host=HOST                  Network host to sniff on (default all)
        -d, --discard=THRESH             Discard keys with request/sec rate below THRESH
        -r, --refresh=MS                 Refresh the stats display every MS milliseconds
            --sniff-time=MS              Allow at least this much time to process packets
        -s, --[no-]refresh-stats         Refresh (clear) stats on display refresh
        -h, --help                       Show usage info

## User interface commands

The following key commands are available in the console UI:

* `C` - sort by number of calls (default)
* `S` - sort by object size
* `B` - sort by bandwidth
* `T` - toggle sorting by ascending / descending order
* `Q` - quits

## Status bar

The following details are displayed in the status bar

* `sort mode` - the current sort mode and ordering
* `keys` - total number of keys in the metrics table
* `packets` - packets received and dropped by libpcap (% is percentage of packets dropped)
* `rt` - the time taken to sort and render the stats
* `reqs` - the total number of requests recorded
* `KB` - the total number of kilobytes of requests recorded
* `elapsed` - the total runtime
* `res/s` - requests per second
* `req/k` - average requests per key

## Filtering

Use of `--agg-filter` will have two results:
* only keys matching the supplied regex will be reported
* keys will be aggregated by the data matched by the first capture group

In order to prevent other `()` grouping from being a capture group, use `?:` in
each group that should be non-capturing.

Aggregated keys are marked with a trailing `*` in the display. When keys are
aggregated, there is no meaningful object size to show, so the size is
displayed as -1; this also allows filtering on object size in order to put
aggregated keys at the top or the bottom of the list.

Note that most of the following examples include single quotes around the filter;
these are necessary in order to prevent shells from interpreting special
characters.

Example: match any key starting with "foo:" but do not aggregate.
`--agg-filter=^foo:`

Example: match any key starting with "foo:" and aggregate.
`--agg-filter='^(foo:)'`

Example: match any key starting with "foo:" or "bar:" and aggregate.
`--agg-filter='^((?:foo|bar):)'`

Example: aggregate any key starting with "foo:" or "bar:"; display the rest
without aggregation.
`--agg-filter='^((?:foo|bar):|.+)'`

Example: aggregate any key starting with "foo:" or "bar:"; display the rest
with aggregation.
`--agg-filter='(^(?:foo|bar)|^)'`

## Performance

Performance can get poor when many keys have been recorded; this requires a
large amount of processing for each display loop. When the display loop gets
slow, then the pcap buffer may not be serviced frequently enough, leading to
packet loss.

Options which affect performance are:

### --agg-filter

This increases load on the sniffer, but if it causes substantial key
aggregation, then the UI will need to do less work. Results may vary.

### --refresh

When the refresh delay is low, more time is spent rendering the stats, leaving
less time available to process packets. `mctop` may not be able to meet the
specified refresh delay, particularly when many keys accumulate.

### --sniff-time

If the refresh delay is low compared to the number of keys to process, then the
time available to process packets is reduced. This option provides a minimum
amount of time reserved to process packets, overriding `--refresh` as
necessary.

### --refresh-stats

This will keep the working set of keys low as long as --refresh is not set too
high. Note that this gives a more traditional top-like behavior rather than
accumulating stats over the entire run time.

## Changelog

* 2012-12-14 - Now compatible with Ruby 1.8.x (tested on 1.8.7-p371)

## Known issues / Gotchas

### ruby-pcap drops packets at high volume
from my testing the ruby-pcap native interface to libpcap struggles to keep up with high packet rates (in what we see on a production memcache instance) you can keep an eye on the packets recv/drop and loss percentage on the status bar at the bottom of the UI to get an idea of the packet

### No binary protocol support
There is currently no support for the binary protocol. However, if someone is using it and would like to submit a patch, it would be welcome.
