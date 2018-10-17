Ship the example email templates as part of the package

**Note**: if you deploy your Synapse instance from a git checkout or a github
snapshot URL, then this means that the example email templates will no longer
be installed in `res/templates`. If you have email notifications enabled, you
should ensure that `email.template_dir` is either configured to point at a
directory where you have installed customised templates, or leave it unset to
use the default templates.

The configuration parser will try to detect the situation where
`email.template_dir` is incorrectly set to `res/templates` and do the right
thing, but will warn about this.