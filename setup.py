from setuptools import setup

setup(
    name='cubite_api',
    version='0.0.1',
    license='MIT',
    description='Extending Open edX with Cubite APIs',
    entry_points={
        'lms.djangoapp': [
            'cubite_api = cubite_api.apps:CubiteAPIsConfig',
        ],
},
)