# bluecat-api-v2-public

Setup:
These scripts use enviroment variables.  To start, copy the file to somewhere safe, like ~/.ssh/ in linux (use any filename you like):
    filename=~/.ssh/bluecat.env
    cp bluecat.example.env $filename
Set the permissions to owner only:
    chmod 600 $filename
Then edit the file and fill in the server name, user name, password, Configuration name, and View name.
Source the file to set the environment variables:
    source $filename

There are a few directories here:    
    curl - Simple bash scripts using curl to illustrate the steps, and for testing.
    python - Better scripts with lots of options built in.
