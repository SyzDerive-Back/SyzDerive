

# SyzDerive

------

### Setup

#### Manually setup

##### Let's warm up

```bash
apt-get update
apt-get -y install git python3 python3-pip python3-venv sudo
git clone https://github.com/SyzDerive/SyzDerive.git
cd SyzDerive/
python3 -m venv venv
. venv/bin/activate
pip3 install -r requirements.txt
```

##### Install required packages and compile essential tools

```bash
python3 SyzDerive --install-requirements
```

------

### Tutorial

<a name="Run_one_case"></a>

#### Run one case

```bash
python3 SyzDerive -i bf4bb7731ef73b83a3b4 ...
```

#### Run cases from cache

```bash
python3 SyzDerive --use-cache --cache-file cases.json
```

#### Run fuzzing

```bash
python3 SyzDerive -i bf4bb7731ef73b83a3b4 -KF --timeout-kernel-fuzzing 2
```

See more usage of SyzDerive by `python3 SyzDerive -h`

