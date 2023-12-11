# Documentation Website Files and Assets

This directory contains extra files for modifying the look and functionality of 
[mdbook](https://github.com/rust-lang/mdBook), the documentation software that's
used to generate Synapse's documentation website.

The configuration options in the `output.html` section of [book.toml](../../book.toml)
point to additional JS/CSS in this directory that are added on each page load. In
addition, the `theme` directory contains files that overwrite their counterparts in
each of the default themes included with mdbook.

Currently we use these files to generate a floating Table of Contents panel. The code for
which was partially taken from
[JorelAli/mdBook-pagetoc](https://github.com/JorelAli/mdBook-pagetoc/)
before being modified such that it scrolls with the content of the page. This is handled
by the `table-of-contents.js/css` files. The table of contents panel only appears on pages
that have more than one header, as well as only appearing on desktop-sized monitors.

We remove the navigation arrows which typically appear on the left and right side of the
screen on desktop as they interfere with the table of contents. This is handled by
the `remove-nav-buttons.css` file.

Finally, we also stylise the chapter titles in the left sidebar by indenting them
slightly so that they are more visually distinguishable from the section headers
(the bold titles). This is done through the `indent-section-headers.css` file.

In addition to these modifications, we have added a version picker to the documentation.
Users can switch between documentations for different versions of Synapse.
This functionality was implemented through the `version-picker.js` and
`version-picker.css` files.

More information can be found in mdbook's official documentation for
[injecting page JS/CSS](https://rust-lang.github.io/mdBook/format/config.html)
and
[customising the default themes](https://rust-lang.github.io/mdBook/format/theme/index.html).