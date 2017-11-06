import os.path
import botocore.loaders
from botocore.loaders import *

class Loader(botocore.loaders.Loader):
    ECSBOTO3_ROOT = os.path.dirname(os.path.abspath(__file__))
    BUILTIN_DATA_PATH = os.path.join(ECSBOTO3_ROOT, 'data')

