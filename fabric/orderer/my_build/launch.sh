pushd ..
go build -tags nopkcs11 -o ./my_build/orderer.exe -gcflags "-N -l"
popd
cp orderer.exe ./test2
cp orderer.exe ./test3
cp orderer.exe ./test4

tmux new-session \; \
splitw -h -p 90 "./orderer.exe; bash" \; \
splitw -h -p 50 "pushd test2; ./orderer.exe; popd; bash" \; \
selectp -t 1 \; \
splitw -v -p 50 "pushd test3; ./orderer.exe; popd; bash" \; \
selectp -t 3 \; \
splitw -v -p 50 "pushd test4; ./orderer.exe; popd; bash" \; \
selectp -t 0
