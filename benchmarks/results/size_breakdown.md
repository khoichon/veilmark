# Held-out image results by image size

Generated from `image-heldout/records.jsonl` and `image-heldout-subtle/records.jsonl`. Large = ≥ 0.8 MP (hubble, retina, motorcycle-2x, flat-ui, two illustrations); small = < 0.3 MP (chelsea, clock, coins, colorwheel, logo, text-page, gravel, immunohistochemistry are 0.07–0.26 MP).

## strength 1.0 (balanced)

| Attack | Payload, large images | Payload, small images |
|---|---|---|
| none | 100% [76-100] (n=12) | 75% [51-90] (n=16) |
| jpeg-75 | 100% [76-100] (n=12) | 69% [44-86] (n=16) |
| jpeg-50 | 92% [65-99] (n=12) | 38% [18-61] (n=16) |
| webp-80 | 83% [55-95] (n=12) | 38% [18-61] (n=16) |
| scale-0.5 | 92% [65-99] (n=12) | 12% [3-36] (n=16) |
| scale-0.75 | 100% [76-100] (n=12) | 31% [14-56] (n=16) |
| crop-50 | 92% [65-99] (n=12) | 62% [39-82] (n=16) |
| crop-25 | 67% [39-86] (n=12) | 38% [18-61] (n=16) |
| rotate-10 | 92% [65-99] (n=12) | 50% [28-72] (n=16) |
| blur-1 | 100% [76-100] (n=12) | 75% [51-90] (n=16) |
| noise-12 | 100% [76-100] (n=12) | 38% [18-61] (n=16) |
| combo-screenshot-like | 100% [76-100] (n=12) | 56% [33-77] (n=16) |
| combo-social-media | 100% [76-100] (n=12) | 0% [0-19] (n=16) |
| combo-crop50-scale0.7-jpeg75 | 83% [55-95] (n=12) | 0% [0-19] (n=16) |

## strength 0.6 (subtle)

| Attack | Payload, large images | Payload, small images |
|---|---|---|
| none | 83% [55-95] (n=12) | 56% [33-77] (n=16) |
| jpeg-75 | 83% [55-95] (n=12) | 0% [0-19] (n=16) |
| jpeg-50 | 33% [14-61] (n=12) | 0% [0-19] (n=16) |
| webp-80 | 25% [9-53] (n=12) | 0% [0-19] (n=16) |
| scale-0.5 | 50% [25-75] (n=12) | 12% [3-36] (n=16) |
| scale-0.75 | 50% [25-75] (n=12) | 25% [10-49] (n=16) |
| crop-50 | 67% [39-86] (n=12) | 44% [23-67] (n=16) |
| crop-25 | 42% [19-68] (n=12) | 25% [10-49] (n=16) |
| rotate-10 | 42% [19-68] (n=12) | 31% [14-56] (n=16) |
| blur-1 | 83% [55-95] (n=12) | 56% [33-77] (n=16) |
| noise-12 | 25% [9-53] (n=12) | 0% [0-19] (n=16) |
| combo-screenshot-like | 83% [55-95] (n=12) | 12% [3-36] (n=16) |
| combo-social-media | 17% [5-45] (n=12) | 0% [0-19] (n=16) |
| combo-crop50-scale0.7-jpeg75 | 25% [9-53] (n=12) | 0% [0-19] (n=16) |

