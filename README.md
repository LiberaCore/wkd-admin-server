# wkd-admin-server
[![Maintainability](https://api.codeclimate.com/v1/badges/45d088f65a05b98cf43f/maintainability)](https://codeclimate.com/github/LiberaCore/wkd-admin-server/maintainability)
[![Test Coverage](https://api.codeclimate.com/v1/badges/45d088f65a05b98cf43f/test_coverage)](https://codeclimate.com/github/LiberaCore/wkd-admin-server/test_coverage)
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
