import datolite as dt

dt.Patcher(
  "testing/test",
  [
    "testing/stringPatch.dpt"
  ]
).patch()
