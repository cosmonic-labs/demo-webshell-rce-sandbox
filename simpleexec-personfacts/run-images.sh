echo -e "Running images on ports 8001 - 8005.. \e[34mBlue"
docker run -p 8001:8080 -t simple-golang &
docker run -p 8002:8080 -t simple-fedora &
docker run -p 8003:8080 -t simple-ubuntu &
docker run -p 8004:8080 -t simple-alpine &
docker run -p 8005:8080 -t simple-scratch &
echo -e "Complete \e[34mBlue"
