#!/bin/bash

# Build the Docker image
docker build -t unittest-image .

# Run the Docker container
docker run --rm -v "$(pwd)/test:/app/test" unittest-image python -m unittest discover -s /app/test -p 'test_*.py'
