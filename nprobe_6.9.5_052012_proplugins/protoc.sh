rm ./fastbit.pb.cc ./fastbit.pb.h
protoc --cpp_out=./ fastbit.proto 
