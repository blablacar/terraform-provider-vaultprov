package planmodifiers

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// BoolDefaultValue accepts a types.Bool value and uses the supplied value to set a default
// if the config for the attribute is null.
func BoolDefaultValue(val types.Bool) planmodifier.Bool {
	return &boolDefaultValueAttributePlanModifier{val}
}

type boolDefaultValueAttributePlanModifier struct {
	val types.Bool
}

func (d *boolDefaultValueAttributePlanModifier) Description(ctx context.Context) string {
	return fmt.Sprintf("If not configured, defaults to %t", d.val.ValueBool())
}

func (d *boolDefaultValueAttributePlanModifier) MarkdownDescription(ctx context.Context) string {
	return d.Description(ctx)
}

// PlanModifyBool checks that the value of the attribute in the configuration and assigns the default value if
// the value in the config is null. This is a destructive operation in that it will overwrite any value
// present in the plan.
func (d *boolDefaultValueAttributePlanModifier) PlanModifyBool(ctx context.Context, req planmodifier.BoolRequest, resp *planmodifier.BoolResponse) {
	// Do not set default if the attribute configuration has been set.
	if !req.ConfigValue.IsNull() {
		return
	}

	resp.PlanValue = d.val
}
