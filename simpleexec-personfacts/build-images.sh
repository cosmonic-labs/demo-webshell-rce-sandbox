echo -e "Building Docker images.. \e[34mBlue"
echo -e "Building alpine.. \e[34mBlue"
docker build -t simple-alpine -f Dockerfile.alpine .
echo -e "Building fedora.. \e[34mBlue"
docker build -t simple-fedora -f Dockerfile.fedora .
echo -e "Building golang.. \e[34mBlue"
docker build -t simple-golang -f Dockerfile.golang .
echo -e "Building scratch.. \e[34mBlue"
docker build -t simple-scratch -f Dockerfile.scratch .
echo -e "Building ubuntu.. \e[34mBlue"
docker build -t simple-ubuntu -f Dockerfile.ubuntu .
echo -e "Complete \e[34mGreen"
echo -e "\e[0mNormal Text"
