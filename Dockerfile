FROM archlinux/base

RUN mkdir -p /app
COPY . /app
WORKDIR /app
RUN pacman --noconfirm -Sy ruby ruby-rdoc gcc make
RUN gem install --no-user-install bundler
RUN bundle install

ENTRYPOINT ruby dns.rb


