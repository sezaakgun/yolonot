"""Training-data pipeline for a local System One judge for yolonot.

The model answers the same typed questions yolonot's typed judge sends
(``ml/spec/yolonot_systemone.json``, generated from ``decision.go``), so a
fine-tuned checkpoint served over ``/v1/systemone`` drops into the judge
chain with no Go changes.
"""
