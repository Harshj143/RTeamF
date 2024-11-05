# Base image
FROM kalilinux/kali-rolling AS kali

# Update and install system dependencies
RUN apt-get update && apt-get install -y \
    git \
    wget \
    python3 \
    python3-pip \
    && rm -rf /var/lib/apt/lists/*

# Set up Python environment
RUN pip3 install --upgrade pip

#working directory
WORKDIR /opt

# Installing tools
RUN apt-get update && apt-get install -y \
    sublist3r \
    subfinder \
    assetfinder \
    nmap \
    wig \
    nuclei \
    httprobe \
    unzip

#Install Aquatone
WORKDIR /opt
RUN wget https://github.com/michenriksen/aquatone/releases/download/v1.7.0/aquatone_linux_amd64_1.7.0.zip
RUN unzip aquatone_linux_amd64_1.7.0.zip
RUN cp aquatone /usr/bin/

#Install LinkFinder
WORKDIR /opt
RUN git clone https://github.com/GerbenJavado/LinkFinder.git
WORKDIR /opt/LinkFinder
RUN pip3 install -r requirements.txt
RUN python3 setup.py install

WORKDIR /opt

RUN wget -q -O - https://dl-ssl.google.com/linux/linux_signing_key.pub | apt-key add -
RUN echo "deb [arch=amd64] http://dl.google.com/linux/chrome/deb/ stable main" >> /etc/apt/sources.list.d/google.list
RUN apt-get update && apt-get install -y \
    google-chrome-stable \
    && rm -rf /var/lib/apt/lists/*

RUN wget -O /tmp/chromedriver.zip https://chromedriver.storage.googleapis.com/114.0.5735.90/chromedriver_linux64.zip
RUN unzip /tmp/chromedriver.zip -d /usr/local/bin/
   
WORKDIR /opt
COPY requirement.txt  ./
RUN pip3 install -r requirement.txt
WORKDIR /usr/share/wig
COPY /Require/wig .
WORKDIR /usr/local/lib/python3.11/dist-packages/Wappalyzer
COPY /Require/Wappalyzer.py .
COPY /Require/WebPage.py .
WORKDIR /usr/local/lib/python3.11/dist-packages/Wappalyzer/data
COPY /Require/technologies.json .
COPY /Require/apps.json .

WORKDIR /usr/lib/python3/dist-packages
COPY /Require/sublist3r.py .

WORKDIR /opt/results
COPY /rtf.sh .
RUN chmod +x rtf.sh
CMD ["./rtf.sh"]


