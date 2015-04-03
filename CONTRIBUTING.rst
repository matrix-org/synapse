Contributing code to Matrix
===========================

Everyone is welcome to contribute code to Matrix
(https://github.com/matrix-org), provided that they are willing to license
their contributions under the same license as the project itself. We follow a
simple 'inbound=outbound' model for contributions: the act of submitting an
'inbound' contribution means that the contributor agrees to license the code
under the same terms as the project's overall 'outbound' license - in our
case, this is almost always Apache Software License v2 (see LICENSE).

How to contribute
~~~~~~~~~~~~~~~~~

The preferred and easiest way to contribute changes to Matrix is to fork the
relevant project on github, and then create a pull request to ask us to pull
your changes into our repo
(https://help.github.com/articles/using-pull-requests/)

**The single biggest thing you need to know is: please base your changes on
the develop branch - /not/ master.**

We use the master branch to track the most recent release, so that folks who
blindly clone the repo and automatically check out master get something that
works. Develop is the unstable branch where all the development actually
happens: the workflow is that contributors should fork the develop branch to
make a 'feature' branch for a particular contribution, and then make a pull
request to merge this back into the matrix.org 'official' develop branch. We
use github's pull request workflow to review the contribution, and either ask
you to make any refinements needed or merge it and make them ourselves. The
changes will then land on master when we next do a release.

We use Jenkins for continuous integration (http://matrix.org/jenkins), and
typically all pull requests get automatically tested Jenkins: if your change breaks the build, Jenkins will yell about it in #matrix-dev:matrix.org so please lurk there and keep an eye open.

Code style
~~~~~~~~~~

All Matrix projects have a well-defined code-style - and sometimes we've even
got as far as documenting it... For instance, synapse's code style doc lives
at https://github.com/matrix-org/synapse/tree/master/docs/code_style.rst.

Please ensure your changes match the cosmetic style of the existing project,
and **never** mix cosmetic and functional changes in the same commit, as it
makes it horribly hard to review otherwise.

Attribution
~~~~~~~~~~~

Everyone who contributes anything to Matrix is welcome to be listed in the
AUTHORS.rst file for the project in question. Please feel free to include a
change to AUTHORS.rst in your pull request to list yourself and a short
description of the area(s) you've worked on. Also, we sometimes have swag to
give away to contributors - if you feel that Matrix-branded apparel is missing
from your life, please mail us your shipping address to matrix at matrix.org and we'll try to fix it :)

Sign off
~~~~~~~~

In order to have a concrete record that your contribution is intentional
and you agree to license it under the same terms as the project's license, we've adopted the
same lightweight approach that the Linux Kernel
(https://www.kernel.org/doc/Documentation/SubmittingPatches), Docker
(https://github.com/docker/docker/blob/master/CONTRIBUTING.md), and many other
projects use: the DCO (Developer Certificate of Origin:
http://developercertificate.org/). This is a simple declaration that you wrote
the contribution or otherwise have the right to contribute it to Matrix::

    Developer Certificate of Origin
    Version 1.1

    Copyright (C) 2004, 2006 The Linux Foundation and its contributors.
    660 York Street, Suite 102,
    San Francisco, CA 94110 USA

    Everyone is permitted to copy and distribute verbatim copies of this
    license document, but changing it is not allowed.

    Developer's Certificate of Origin 1.1

    By making a contribution to this project, I certify that:

    (a) The contribution was created in whole or in part by me and I
        have the right to submit it under the open source license
        indicated in the file; or

    (b) The contribution is based upon previous work that, to the best
        of my knowledge, is covered under an appropriate open source
        license and I have the right under that license to submit that
        work with modifications, whether created in whole or in part
        by me, under the same open source license (unless I am
        permitted to submit under a different license), as indicated
        in the file; or

    (c) The contribution was provided directly to me by some other
        person who certified (a), (b) or (c) and I have not modified
        it.

    (d) I understand and agree that this project and the contribution
        are public and that a record of the contribution (including all
        personal information I submit with it, including my sign-off) is
        maintained indefinitely and may be redistributed consistent with
        this project or the open source license(s) involved.
        
If you agree to this for your contribution, then all that's needed is to
include the line in your commit or pull request comment::

    Signed-off-by: Your Name <your@email.example.org>
    
...using your real name; unfortunately pseudonyms and anonymous contributions
can't be accepted. Git makes this trivial - just use the -s flag when you do
``git commit``, having first set ``user.name`` and ``user.email`` git configs
(which you should have done anyway :)

Conclusion
~~~~~~~~~~

That's it!  Matrix is a very open and collaborative project as you might expect given our obsession with open communication.  If we're going to successfully matrix together all the fragmented communication technologies out there we are reliant on contributions and collaboration from the community to do so.  So please get involved - and we hope you have as much fun hacking on Matrix as we do!