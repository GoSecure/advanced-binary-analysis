# Advanced Binary Analysis

This repository contains the materials for the Advanced Binary
Analysis workshop given by [@alxbl][1] at NorthSec 2020.


[1]: https://segfault.me

## Install

This repository uses git LFS to store large files, make sure you have the `git-lfs` package installed, then run

```sh
git lfs install
git lfs checkout
```

to ensure that all the static assets are available.

## Usage

Serve `html/` with your favorite built-in HTTP server:

```sh
cd html && python3 -m http.server 8080
firefox http://localhost:8080
```


Build and run the workshop environment:

```
# Build docker image
docker build -t advanced-binary-analysis .

# Create workshop container instance
docker run --name aba-workshop -v$(pwd):/home/lab -p 8888:8888 -it advanced-binary-analysis

```


After running the workshop, to clean up the environment:

```sh
# Remove docker container when done
docker stop aba-workshop && docker rm aba-workshop

# Remove docker image to reclaim disk space.
docker rmi advanced-binary-analysis
```



# License

- The code provided as part of the workshop is licensed under MIT.
- The material (visual support, walkthrough, notes) is licensed under CC-BY-SA.

See LICENSE for more details.
