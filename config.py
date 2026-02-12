class Config():

    # Input directory for pcap/pcapng files
    dir_input = "./data/" 

    
    # Send data to Elasticsearch/ELK
    user_elastic = False
    
    # Elasticsearch API URL
    # elastic_url = "http://localhost:9200" 
    elastic_url = "http://elasticsearch:9200" # When using inside a docker container


    # Generate CSV file with logs
    user_csv = True 

    # Generate SQLite database with logs
    user_db = True 
    
    # Directory for CSV and SQLite database
    databases_dir = "./databases/" 

    # Output directory for rules
    dir_output = "./output/" 

    

    # Generate a visualization with AfterGlow
    # Only on Linux kernels
    user_afterglow = False
    
    # Remove rules where source and destination are in the same /24 subnet
    remove_same_network = True 

    

    # Use top ports from capture instead of common ports template
    # Used to determine public ports, e.g., 80, 443, 53
    auto_any_rules = False 

    # Threshold to consider a port as "public/global"
    # If a port is used by more than X different destinations, 
    # create an "any" rule for this port instead of specific rules
    global_port_threshold = 20 
    
    # Threshold to consider a server as "public" 
    # If a server receives connections from more than X different sources,
    # use stateful rules instead of listing each source
    public_server_threshold = 15

    # Range of TCP random ports considered as stateful
    tcp_random_range = range(32768, 65536) 

    # Max different destination ports to create a response rule (ESTABLISHED, RELATED)
    # Usually due to TCP random ports
    max_uniques_ports = 20 

    

    

