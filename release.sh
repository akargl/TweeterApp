RELEASE_FOLDER=release

rm -rf $RELEASE_FOLDER
mkdir -p $RELEASE_FOLDER
cp README.md $RELEASE_FOLDER
cp Dockerfile $RELEASE_FOLDER
cp docker-compose.yml $RELEASE_FOLDER
cp requirements.txt $RELEASE_FOLDER
cp *.py $RELEASE_FOLDER
cp -r app $RELEASE_FOLDER
mkdir -p $RELEASE_FOLDER/tests/test_data
cp tests/test_data/* $RELEASE_FOLDER/tests/test_data
