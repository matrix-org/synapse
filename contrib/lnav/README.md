# `lnav` config for Synapse logs

[lnav](https://lnav.org/) is a log-viewing tool. It is particularly useful when 
you need to interleave multiple log files, or for exploring a large log file
with regex filters. The downside is that it is not as ubiquitous as tools like
`less`, `grep`, etc.

This directory contains an `lnav` [log format definition](
    https://docs.lnav.org/en/v0.10.1/formats.html#defining-a-new-format
) for Synapse logs as
emitted by Synapse with the default [logging configuration](
    https://matrix-org.github.io/synapse/latest/usage/configuration/config_documentation.html#log_config
). It supports lnav 0.10.1 because that's what's packaged by my distribution.

This should allow lnav:

- to interpret timestamps, allowing log interleaving;
- to interpret log severity levels, allowing colouring by log level(!!!);
- to interpret request IDs, allowing you to skip through a specific request; and
- to highlight room, event and user IDs in logs.

See also https://gist.github.com/benje/e2ab750b0a81d11920d83af637d289f7 for a
 similar example.

## Example

[![asciicast](https://asciinema.org/a/556133.svg)](https://asciinema.org/a/556133)

## Tips

- `lnav -i /path/to/synapse/checkout/contrib/lnav/synapse-log-format.json`
- `lnav my_synapse_log_file` or `lnav synapse_log_files.*`, etc.
- `lnav --help` for CLI help.

Within lnav itself:

- `?` for help within lnav itself.
- `q` to quit.
- `/` to search a-la `less` and `vim`, then `n` and `N` to continue searching 
  down and up.
- Use `o` and `O` to skip through logs based on the request ID (`POST-1234`, or
  else the value of the [`request_id_header`](
    https://matrix-org.github.io/synapse/latest/usage/configuration/config_documentation.html?highlight=request_id_header#listeners
  ) header). This may get confused if the same request ID is repeated among 
  multiple files or process restarts.
- ???
- Profit
