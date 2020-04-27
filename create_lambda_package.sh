CWD=$(pwd)
cd $HOME/venv/getConjurSecret
source bin/activate

cd lib/python3.7/site-packages

rm -rf conjur-authn-iam-client-python
git clone https://github.com/cyberark/conjur-authn-iam-client-python.git
cd conjur-authn-iam-client-python
pip3 install .

cd ..
zip -r function.zip ./

mv function.zip $CWD/lambda_function_package.zip

