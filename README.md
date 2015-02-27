
OpenNOP-SoloWAN

    OpenNOP-SoloWAN is an enhanced version of the Open Network Optimization 
    Platform (OpenNOP). OpenNOP-SoloWAN implements a modern dictionary based
    compression algorithm to add deduplication capabilities to OpenNOP. 

    SoloWAN is a project of the Center for Open Middleware (COM) of Universidad
    Politecnica de Madrid which aims to experiment with open-source based WAN 
    optimization solutions.

License

    OpenNOP-SoloWAN is distributed as free software under GPL version 3 
    license. See COPYING file for details on copying and usage.

    Copyright (C) 2014 OpenNOP.org (yaplej@opennop.org) for the original 
    OpenNOP code.

    Copyright (C) 2014 Center for Open Middleware (COM), Universidad 
    Politecnica de Madrid, SPAIN, for the added modules and the modifications 
    to the OpenNOP original code.

    SoloWAN:                 
        solowan@centeropenmiddleware.com
        https://github.com/centeropenmiddleware/solowan/wiki

    OpenNOP:
        http://www.opennop.org

    Center for Open Middleware (COM):
        http://www.centeropenmiddleware.com

    Universidad Politecnica de Madrid (UPM):
        http://www.upm.es   

Installation

    To install OpenNOP-SoloWAN:

    - Download code from git repository:
        git clone https://github.com/centeropenmiddleware/solowan.git

    - Install required packages:
        + For Debian/Ubuntu:
            apt-get install iptables build-essential autoconf autogen psmisc \
                            libnetfilter-queue-dev libreadline-dev
        + For RedHat/Fedora:
            yum install ...

    - Compile and install:
        cd solowan/opennopd/opennop-daemon
        ./autogen.sh 
        ./configure
        make
        make install

Docker configuration

    OpenNOP-SoloWAN is able to run inside a docker container. 

    - Download and install docker software. Refer to docker's official website for 
      installation instructions (https://docs.docker.com/installation)

    - Run OpenNOP-SoloWAN container:

	> docker run -d --privileged --net=host solowan/solowan:v0.1 opennopd -n

    - Edit configuration parameters

	> docker ps -a --no-trunc -q    # Get Container ID
	> docker attach -n <container-id> vi /etc/opennop/opennop.conf
	> docker stop <container-id>    # Stop the container
	> docker start <container-id>

Manual

  OpenNOP daemon

  Usage: opennopd -h -n

  - Parameters:
      + n: Don't fork off as a daemon.
	  + h: Prints usage message.
	  + Without parameters: Opennopd runs as a Unix Daemon. The log messages are
        saved to /var/log/syslog file.

  - Configuration file. At startup OpenNOP read a configuration file located 
    in /etc/opennop/opennop.conf. The following parameters can be specified 
    in the file:
	  - optimization: Sets the optimization algorithm. 
        Values: compression, deduplication. 
        Default to: compression.
      - localid: The local IP used to add the accelerator ID into the 
        compressed packets. Mandatory parameter. Without a valid IP opennopd
        does not start.
	  - thrnum: Number of threads used for optimization. In case of using 
        deduplication, each thread uses his own dictionary. Recommended in 
        to set above 1 in case of multiple simultaneous transfers. 
        Defaults to: 1.
	  - num_pkt_cache_size: Size in number of packets of the packets cache. 
        This value should be a power of 2. In case the value is not a power 
        of 2, it is rounded to the next lower power of 2. 
        Defaults to: 131072.
      - pkt_size. Maximum size of packets in bytes. Should be aligned with 
        the maximum transmission unit (MTU). 
        Defaults to: 1500.
      - fp_per_pkt. Number of FPs calculated per packet.
        Defaults to: 32.
        Maximum value to: 32.
      - fps_factor. FP hash table factor. The size of FP hash table is calculated multiplying num_pkt_cache_size by fps_factor.
        Defaults to: 4.
        Maximum value: 4.

  Memory usage: A rough estimate of the memory required by the optimizer's data structures is given by (in bytes):

      2 x thrnum x num_pkt_cache_size x (pkt_size + 64 x fp_per_pkt x fps_factor)

      Where:

          thrnum = Number of threads used for deduplication tasks. If you have enough RAM, the ideal value should be the number of cores of your CPU, but it can work with a single thread.
          num_pkt_cache_size = Maximum number of packets that can be cached by the optimizer. The larger, the better (more redundancy can be detected as the system has more memory).
          pkt_size = Maximum packet size (bytes). The default value is the Ethernet MTU (1500 B). This value should not be modified in most environments.
          fp_per_pkt = Number of patterns detected in each cached packet. The maximum value is 32. The larger, the better (more patterns can be identified for each cached packet). So, 32 is the best choice, but 16 can yield good results.
          fps_factor = Used to adjust the number of entries of a hash table. The recommended value is 2.

      You should also take into account that the operating system also needs enough RAM to work, in addition to the memory occupied by the optimizer, so the optimizer PC must have a memory size larger than the previous estimate.

      If your RAM is limited, a reasonable parameter choice is: single thread, 1500 B packet size, fp_per_pkt=16, fps_factor=2, and adjust num_pkt_cache_size to be as large as possible.  If you have more RAM, set fps_per_pkt to 32 and adjust num_pkt_cache_size to be as large as possible. If RAM size is large, you can also increase thrnum to improve performance.


  OpenNOP command line client. It allows interacting with opennopd to change 
  configuration and get information from it. 

  Usage:  opennop
          opennop [command] [parameter]

  With no arguments, opennop starts in interactive (shell) mode and waits for
  the user to type commnds. With arguments, opennop executes the requested 
  command and returns the result.

  Commands:
	- compression [enable, disable]         
        -> Enable or disable compression optimization. 
	- deduplication [enable, disable]       
        -> Enable or disable deduplication optimization.
	- traces [disable]                      
        -> Disable all the traces.
	- traces [enable level]                 
        -> Set all the trace level. Level must be a number between 1 and 3. 
	- traces [enable traces_name level]     
        -> Set the trace level of "traces_name" at level. Possible values of 
           traces_name: dedup, local_update_cache, put_in_cache, recover_dedup, 
           uncomp, update_cache, update_cache_rtx. Level must be a number 
           between 1 and 3. 
	- traces [disable traces_name]
        -> Disable the traces "traces_name". Possible values of traces_name: 
           dedup, local_update_cache, put_in_cache, recover_dedup, uncomp, 
           update_cache, update_cache_rtx.
	- traces [mask] [orr and nand] [Number]
        -> Performs a logical 'orr', 'and' or 'nand' operation with the current 
           trace mask.
	- reset [stats] [in_dedup out_dedup]
        -> Reset the compressor statistics (in_dedup) or decompressor 
           statistics (out_dedup).
	- show [show_parameters]
        -> Display information sended by opennopd.
		* [show_parameters]:
			- stats in_dedup: Show the compressor statistics.
			- stats out_dedup: Show the decompressor statistics.
			- version: Show the version of the opennop.
			- compression: Show if the compression is enabled or disabled.
			- deduplication: Show if the deduplication is enabled or disabled.
			- workers: Show the statistics of the workers.
			- fetcher:Show the statistics of the fetcher.
			- sessions: Show the statistics of the sessions established.
			- traces mask: Show the traces mask.

Traffic forwarding

  To make the traffic available to OpenNOP it has to be redirected from the 
  Linux kernel to the user-space where the daemon runs. This has been 
  implemented with a packets queue by using the libnetfilter-queue
  library.

  OpenNOP-SoloWAN has been mainly tested using iptables for the redirection
  task. iptables allows to specify a libnetfilter-queue (NFQUEUE) as the 
  destination target in order to delegate the process of network packets 
  to a userspace program. In userspace, opennopd uses libnetfilter_queue 
  to connect to queue 0 and get the traffic from kernel. 

  See below some examples of iptables commands to select the traffic 
  to be forwarded to the opennopd:

	- Redirect ALL the TCP traffic:
		# iptables -A FORWARD -j NFQUEUE --queue-num 0 -p TCP
	- Redirect only the HTTP traffic:
		# iptables -A FORWARD -j NFQUEUE --queue-num 0 -p TCP --sport 80
		# iptables -A FORWARD -j NFQUEUE --queue-num 0 -p TCP --dport 80
	- Redirect FTP control traffic:
		# iptables -A FORWARD -j NFQUEUE --queue-num 0 -p TCP --sport 21
		# iptables -A FORWARD -j NFQUEUE --queue-num 0 -p TCP --dport 21
	- Redirect a range of TCP ports:
		# iptables -A FORWARD -j NFQUEUE --queue-num 0 -p TCP --sport 8000:8999
		# iptables -A FORWARD -j NFQUEUE --queue-num 0 -p TCP --dport 8000:8999

  Note: originally, OpenNOP used a kernel module to do the redirection task. 
  That module is not included in OpenNOP-SoloWAN and has not been extensively 
  tested, although no change made should prevent it from working.


