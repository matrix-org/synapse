# Synapse in Kubernetes

Here you can find a sample configuration for running Synapse in your Kubernetes cluster.

### Is this configuration complete?

By no means. You will need to extend the configuration in ```homeserver.yaml```, tailor it to your specific needs and provide the file as a Secret. The other Synapse configuration files can be provided as ConfigMaps and should not need much editing. 

The various provided Kubernetes specifications are provided as a reference. The only thing that scales horizontally are the generic workers. Stream writers need to be named and scaling those is a lot more involved. How to seperate out the different stream writers is probably something you want to play with.

The configuration is intended as a starting point, exposing the different types of workers, so you can tune and optimize according to your needs. As it is, it's probably not the most optimal way to run your deployment. The example does include most of the load balancing as described [here](https://matrix-org.github.io/synapse/latest/workers.html).

Feel free to contribute.

### Why are there 3 ingresses, each with their own service?

Apparently, when multiple ingresses refer to the same service, only the annotations on the first ingress are used. This is something you now know. I sure didn't when I tried to get load balancing to work. Each ingress needs its own service.