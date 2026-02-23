cargo modules dependencies \
  --manifest-path Cargo.toml --lib \ 
  --no-externs --no-sysroot \
  --no-fns --no-traits \
  --no-modules --no-owns \
  > types.dot

  dot -Tsvg types.dot > types.svg