#!/bin/bash

python3 -m venv /home/ubuntu/viadigitech-env
source /home/ubuntu/viadigitech-env/bin/activate
pip install numpy==1.26.4 matplotlib pandas
deactivate
