FROM python:2.7

# Create the group and user to be used in this container
RUN groupadd tweetrgroup && useradd -m -g tweetrgroup -s /bin/bash tweetr

# Create the working directory (and set it as the working directory)
RUN mkdir -p /home/tweetr/app
WORKDIR /home/tweetr/app

# Install the package dependencies (this step is separated
# from copying all the source code to avoid having to
# re-install all python packages defined in requirements.txt
# whenever any source code change is made)
COPY requirements.txt /home/tweetr/app/
RUN pip install --no-cache-dir -r requirements.txt

# Copy the source code into the container
COPY . /home/tweetr/app

RUN chown -R tweetr:tweetrgroup /home/tweetr

USER tweetr
