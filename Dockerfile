FROM python:2.7

# Create the group and user to be used in this container
RUN groupadd tweetergroup && useradd -m -g tweetergroup -s /bin/bash tweeter

# Create the working directory (and set it as the working directory)
RUN mkdir -p /home/tweeter
WORKDIR /home/tweeter

COPY requirements.txt /home/tweeter
RUN pip install --no-cache-dir -r requirements.txt

# Copy the source code into the container
COPY . /home/tweeter

RUN chown -R tweeter:tweetergroup /home/tweeter

USER tweeter

RUN export FLASK_APP=run.py && flask seeddb
