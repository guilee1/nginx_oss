FROM centos:7
COPY sysctl.conf /etc/sysctl.conf
CMD sysctl -p /etc/sysctl.conf
WORKDIR /usr/local/nginx
COPY nginx /usr/local/nginx
COPY conf /usr/local/nginx/conf
CMD ["/usr/local/nginx/nginx","-g","daemon off;"]