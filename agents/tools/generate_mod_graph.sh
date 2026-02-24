cargo modules dependencies \
  --no-externs \
  --no-fns \
  --no-sysroot \
  --no-traits \
  --no-types \
  --no-uses \
  > mods.dot

dot -Tsvg mods.dot > mods.svg