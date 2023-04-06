## ARJ-Stack: Python based E-signature Impementation using AWS KMS and JWT

### Requirements

| Name | Version |
|------|---------|
| <a name="requirement_awscli"></a> [awscli](#requirement\_awscli) | 2.9.21 |
| <a name="requirement_python"></a> [python](#requirement\_python) | 3.11.1 |
| <a name="requirement_poetry"></a> [poetry](#requirement\_poetry) | 1.4.1 |


### How to setup the project (if doing it from start rather cloning it)

- Create a directory named `aws-kms-e-signature`
- Run the following commands withint the directory:

```
poetry init
poetry add boto3
poetry add pytest
poetry add pyjwt
```

### How to Run it?

#### Delete the executable directory (if any)

```
rmdir /S lib
```

#### Setup the executable directory

```
mkdir lib\python
copy poetry.lock lib\python
copy pyproject.toml lib\python
copy signature.py lib\python\
cd lib\python
```

#### Export dependencies

```
poetry export --without-hashes --format=requirements.txt > requirements-poetry.txt
```

#### Install dependencies

```
pip install -r requirements-poetry.txt --target . --upgrade
```

#### Run the program

```
python.exe .\signature.py
```

### Output Footprints

<img src="https://github.com/arjstack/aws-kms-e-signature/blob/main/output.png">

### Authors

Module is maintained by [Ankit Jain](https://github.com/ankit-jn) with help from [these professional](https://github.com/arjstack/aws-kms-e-signature/graphs/contributors).