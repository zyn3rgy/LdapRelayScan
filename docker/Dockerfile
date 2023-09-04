FROM python:3.9-slim

#make directory "LdapRelayScan"
RUN mkdir /LdapRelayScan

#copy all files from current directory to "LdapRelayScan" directory
COPY . /LdapRelayScan

#set working directory to "LdapRelayScan"
WORKDIR /LdapRelayScan

#update apt and install proxychains4
RUN apt update && apt install proxychains4 -y

#install all requirements
RUN python3 -m pip install -r requirements_exact.txt

# Set the entrypoint as the bash script to determine if proxy is needed
ENTRYPOINT ["/bin/bash", "/LdapRelayScan/docker/entrypoint.sh"]

