---
title: reverse泛做1
date: 2022-12-11 17:49:17
tags: 逆向
---

## [网鼎杯 2020 青龙组]singal

### 思路1：angr

``` python
import angr
path='./signal.exe'
project=angr.Project(path)
state=project.factory.entry_state()
simgr=project.factory.simgr(state)
simgr.explore(find=0x4017A5,avoid=0x4016E6)
flag=simgr.found[0].posix.dumps(0)[:15]
print(flag)
#flag{757515121f3d478}
```

### 思路2：vm逆向