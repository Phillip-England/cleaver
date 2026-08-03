FROM golang:1.26 AS build

WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 go build -o /cleaver .

FROM scratch

COPY --from=build /cleaver /cleaver
EXPOSE 5544

ENTRYPOINT ["/cleaver"]
CMD ["-addr", "0.0.0.0:5544"]
