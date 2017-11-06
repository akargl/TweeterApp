FROM python:2.7

# Create the group and user to be used in this container
RUN groupadd tweetrgroup && useradd -m -g tweetrgroup -s /bin/bash tweetr

# Create the working directory (and set it as the working directory)
RUN mkdir -p /home/tweetr
WORKDIR /home/tweetr

COPY requirements.txt /home/tweetr
RUN pip install --no-cache-dir -r requirements.txt

# Copy the source code into the container
COPY . /home/tweetr

RUN chown -R tweetr:tweetrgroup /home/tweetr

USER tweetr

RUN export FLASK_APP=run.py && flask seeddb
