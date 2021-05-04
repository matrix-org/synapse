---
name: Bug report
about: Create a report to help us improve

---

<!--

**THIS IS NOT A SUPPORT CHANNEL!**
**IF YOU HAVE SUPPORT QUESTIONS ABOUT RUNNING OR CONFIGURING YOUR OWN HOME SERVER**,
please ask in **#synapse:matrix.org** (using a matrix.org account if necessary)

If you want to report a security issue, please see https://matrix.org/security-disclosure-policy/

This is a bug report template. By following the instructions below and
filling out the sections with your information, you will help the us to get all
the necessary data to fix your issue.

You can also preview your report before submitting it. You may remove sections
that aren't relevant to your particular case.

Text between <!-- and --​> marks will be invisible in the report.

-->

### Description

<!-- Describe here the problem that you are experiencing -->

### Steps to reproduce

- list the steps
- that reproduce the bug
- using hyphens as bullet points

<!--
Describe how what happens differs from what you expected.

If you can identify any relevant log snippets from _homeserver.log_, please include
those (please be careful to remove any personal or private data). Please surround them with
``` (three backticks, on a line on their own), so that they are formatted legibly.
-->

### Version information

<!-- IMPORTANT: please answer the following questions, to help us narrow down the problem -->

<!-- Was this issue identified on matrix.org or another homeserver? -->
- **Homeserver**:

If not matrix.org:

<!--
 What version of Synapse is running?

You can find the Synapse version with this command:

$ curl http://localhost:8008/_synapse/admin/v1/server_version

(You may need to replace `localhost:8008` if Synapse is not configured to
listen on that port.)
-->
- **Version**:

- **Install method**:
<!-- examples: package manager/git clone/pip  -->

- **Platform**:
<!--
Tell us about the environment in which your homeserver is operating
distro, hardware, if it's running in a vm/container, etc.
-->
