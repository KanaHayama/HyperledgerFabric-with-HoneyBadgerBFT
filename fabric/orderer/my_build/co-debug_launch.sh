pushd ..
go build -tags nopkcs11 -o ./my_build/orderer.exe -gcflags "-N -l"
popd
cp orderer.exe ./test2
cp orderer.exe ./test3
cp orderer.exe ./test4

#modify this using tmux
#test2/orderer.exe&
#test3/orderer.exe&
#test4/orderer.exe&

tmux new-session "pushd test2; ./orderer.exe; popd; bash" \; \
splitw -h -p 33 "pushd test4; ./orderer.exe; popd; bash" \; \
selectp -t 0 \; \
splitw -h -p 50 "pushd test3; ./orderer.exe; popd; bash" \; \
detach
