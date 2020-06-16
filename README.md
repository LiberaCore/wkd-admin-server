# wkd-admin-server

Flask RestPlus based API for managing OpenPGP keys in a Web Key Directory.

### Running tests
Install dependencies:

        pip3 install .

Start with gunicorn:

        gunicorn3 --chdir wkd_admin -w 4 -b 127.0.0.1:5000 app:app

Execute the tests in a new terminal:

        ./run_tests.sh

### TODOs:

  * [x] tests
  * [ ] documentation
  * [ ] production setup
    * [ ] nginx
    * [ ] python docblocks
  * [x] temp folder management
  * [ ] temp folder fix path
