package planmodifiers

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// Int64DefaultValue accepts a types.Bool value and uses the supplied value to set a default
// if the config for the attribute is null.
func Int64DefaultValue(val types.Int64) planmodifier.Int64 {
	return &int64DefaultValueAttributePlanModifier{val}
}

type int64DefaultValueAttributePlanModifier struct {
	val types.Int64
}

func (d *int64DefaultValueAttributePlanModifier) Description(ctx context.Context) string {
	return fmt.Sprintf("If not configured, defaults to %d", d.val.ValueInt64())
}

func (d *int64DefaultValueAttributePlanModifier) MarkdownDescription(ctx context.Context) string {
	return d.Description(ctx)
}

// PlanModifyInt64 checks that the value of the attribute in the configuration and assigns the default value if
// the value in the config is null. This is a destructive operation in that it will overwrite any value
// present in the plan.
func (d *int64DefaultValueAttributePlanModifier) PlanModifyInt64(ctx context.Context, req planmodifier.Int64Request, resp *planmodifier.Int64Response) {
	// Do not set default if the attribute configuration has been set.
	if !req.ConfigValue.IsNull() {
		return
	}

	resp.PlanValue = d.val
}
